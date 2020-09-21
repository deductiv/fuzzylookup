#!/usr/bin/env python
# 
# Fuzzylookup search command
# 
# Compares a field in Splunk search results against values in a lookup field
# Supports filtering and masking of data within the lookup, including using data from the event
# 
# Author: J.R. Murray <jr.murray@deductiv.net>
# 
# Version: 1.0.0 (2020-09-11)

from __future__ import unicode_literals
from __future__ import print_function
from builtins import range
from future import standard_library
standard_library.install_aliases()
from builtins import str

import sys, os, traceback
from collections import OrderedDict 
import urllib.parse
import re
import json
import time
import fnmatch
import difflib
from deductiv_helpers import *

# Multithreading
import multiprocessing as mp
from multiprocessing import Pool, Manager #, set_start_method, get_context -- py3 only
from multiprocessing.dummy import Pool as ThreadPool
import threading

# Add lib folders to import path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))

# Jellyfish
import jellyfish as jf

# Splunk
import splunklib.client as client
import splunklib.results as results
from splunklib.searchcommands import StreamingCommand, dispatch, Configuration, Option, validators

logger = setup_logging('fuzzylookup')

def matching_chars(string1, string2):
	# Find the number of characters between two strings that overlap
	count = 0
	length = min(len(string1), len(string2))
	for i in range(0, length):
		if string1[i] == string2[i]:
			count += 1
	return count

def overlap_length(string1, string2):
	sm = difflib.SequenceMatcher(a=string1, b=string2)
	try:
		return sm.find_longest_match(0, len(string1), 0, len(string2) ).size
	except BaseException as e:
		return -1

# Define class and type for Splunk command
@Configuration(local=True)
class fuzzylookup(StreamingCommand):
	doc='''
	**Syntax:**
	| fuzzylookup 
		[ prefix=<string> ]
		[ lookupfilter=<kvpairs> ]
		[ mask=<regex> ]
		[ delete=<regex> ]
		<lookup-table-name> 
		( <lookup-field> [AS <event-field>] ) 
		[ OUTPUT | OUTPUTNEW (<lookup-destfield> [AS <event-destfield>] ) ... ]

	**Description**
	Takes field from search results and compares to a lookup for near-matches
	'''

	prefix = Option(
		doc='''
		**Syntax:** **prefix=***"prefix_text"
		**Description:** Text to prefix all output field names with. Helpful if you just want every lookup field without aliasing each one.''',
		require=False) 

	lookupfilter = Option(
		doc='''
		**Syntax:** **lookupfilter=***"LookupField1=\"local admin\" Lookupfield2=\"*@$email_domain$\""* (wildcard, variable, or literal string match)
		**Description:** Filter for data in the specified lookup to narrow down comparisons''',
		require=False) 

	mask = Option(
		doc='''
		**Syntax:** **mask=***"regular expression"*
		**Description:** Mask pattern for both compared sets of values. Masks the regex matched text before comparing.''',
		require=False, validate=validators.RegularExpression())

	delete = Option(
		doc='''
		**Syntax:** **delete=***"regular expression"*
		**Description:** Deletion pattern for both compared sets of values. Removes the regex matched text before comparing.''',
		require=False, validate=validators.RegularExpression())

	session_key = ''
	splunkd_uri = ''
	service = ''
	lookup_list = []
	lookup_filters_static = []
	lookup_filters_dynamic = []

	lookup = ''
	lookupfield = ''
	searchfield = ''
	#output_fields = []
	output_aliases = OrderedDict()
	# Default output field overwrite setting is True
	output_overwrite = True

	# Store the data from the lookup for each dynamic filter
	# Use a manager as a proxy to allow for cross-process communication
	manager = Manager()
	prepopulated_filter_lookupdata = manager.dict()
	l = manager.list()

	# Define main function
	def stream(self, events):
		logger = setup_logging('fuzzylookup')

		args = [val for val in self._metadata.searchinfo.args[2:] if '=' not in val]

		logger.debug("Arguments: " + str(self._metadata.searchinfo.args[2:]))
		arg_count = len(args)
		arg_index = 0

		# Parse the arguments to the command
		if arg_count >= 3:
			while arg_index < arg_count:
				# Process the lookup name, lookup field, search field
				if self.lookup == '':
					self.lookup = args[arg_index]
					arg_index += 1
				if self.lookupfield == '':
					self.lookupfield = args[arg_index]
					if len(args) >= arg_index + 2:
						if args[arg_index + 1].upper() == 'AS':
							self.searchfield = args[arg_index + 2]
							arg_index += 3
						else:
							self.searchfield = self.lookupfield
							arg_index += 1
					else:
						self.searchfield = self.lookupfield
						arg_index += 1
						
				if arg_index < len(args) and None not in [self.lookup, self.lookupfield, self.searchfield]:
					if args[arg_index].upper() == 'OUTPUT':
						self.output_overwrite = True
					elif args[arg_index].upper() == 'OUTPUTNEW':
						self.output_overwrite = False
					else:
						# Add field to output fields list
						output_field_name = args[arg_index].strip(',')
						#self.output_fields.append(output_field_name)
						if len(args) >= arg_index + 2:
							if args[arg_index + 1].upper() == 'AS':
								self.output_aliases[output_field_name] = args[arg_index + 2]
								arg_index += 2
							else:
								self.output_aliases[output_field_name] = output_field_name
						else:
							self.output_aliases[output_field_name] = output_field_name
					arg_index += 1
		else: 
			logger.critical("Not enough parameters specified to execute fuzzylookup.")
			print("Not enough parameters specified to execute fuzzylookup.")
			exit(1957)

		if None in [self.lookup, self.lookupfield, self.searchfield]:
			logger.critical("Could not parse all arguments for fuzzylookup")
			print("Could not parse all arguments for fuzzylookup")
			exit(1173)
		
		logger.debug("lookup: " + self.lookup)
		logger.debug("lookupfield: " + self.lookupfield)
		logger.debug("searchfield: " + self.searchfield)
		logger.debug("output_overwrite: " + str(self.output_overwrite))
		#logger.debug("output_fields: " + str(self.output_fields))
		logger.debug("output_aliases: " + str(self.output_aliases))


		logger.debug(self.prefix)
		if self.prefix is None:
			self.prefix = ''
		logger.debug("Prefix is " + self.prefix)

		#log beginning of comparison
		logger.info('Comparing %s to %s in %s lookup for fuzzy matches', self.searchfield, self.lookupfield, self.lookup)
		start_time = time.time()

		lookupfilter_str = ''
		# See if we have a lookup filter we can use in the root search
		if self.lookupfilter is not None and len(self.lookupfilter) > 0:
			# Split the filter into multiple key/value filters
			# Break the data into multiple fields, if needed
			# Replace the space delimiter with |, then split by | 
			filter_list = re.sub(r'\s+(\w+=)', '|\g<1>', self.lookupfilter).split('|')
			for f in filter_list:
				logger.debug("filter = " + f)
				filter_re = re.compile(r'^(.*?)([<>=]+)(.*)$')
				m = filter_re.match(f)
				if m is not None:
					filter_obj = {
						'field': m.group(1),
						'op':    m.group(2),
						'value': m.group(3).strip('"')
					}
					# Find the dynamic filters, referencing $fieldname$ from the event
					if re.search(r'\$\w+\$', f) is None:
						self.lookup_filters_static.append(filter_obj)
					else:
						# Find the static filters
						self.lookup_filters_dynamic.append(filter_obj)
				else:
					# Only handle field/value pair filters. Ignore all others.
					logger.info("Ignored filter: %s", f)

			# Build the static filter string to go into the SPL search
			for f in self.lookup_filters_static:
				lookupfilter_str += '{0}{1}"{2}" '.format(f['field'].replace('|', ""), f['op'], f['value'].replace('|', ""))

		logger.debug("Static lookup filter: %s", lookupfilter_str)

		if len(lookupfilter_str) > 0:
			lookup_search = '|inputlookup {0} where {1}="*" | search {2} | eval {1}=lower({1}) | dedup {1}'.format(self.lookup, self.lookupfield, lookupfilter_str)
		else:
			lookup_search = '|inputlookup {0} where {1}="*" | eval {1}=lower({1}) | dedup {1}'.format(self.lookup, self.lookupfield)

		logger.info('Lookup query is: %s' % (lookup_search))
		# Connect via existing session key
		self.session_key = self._metadata.searchinfo.session_key
		self.splunkd_uri = self._metadata.searchinfo.splunkd_uri
		namespace = self._metadata.searchinfo.app
		
		try:
			self.service = client.connect(token=self.session_key)
			logger.info('Successfully connected to %s', str(self.splunkd_uri))
		except BaseException as e:
			logger.error('Error connecting: %s', repr(e))
		# bind incoming search results for reading and extraction of search field
		# execute lookup command and bind results
		logger.info('Attempting to cache lookup of %s', self.lookup)
		
		# Set the URL of the Splunk endpoint
		search_url = '%s/servicesNS/nobody/%s/search/jobs' % (self.splunkd_uri, namespace)
		
		# Set the headers for HTTP requests
		headers = {
			'Authorization': 'Splunk %s' % self.session_key,
			'Content-Type': 'application/x-www-form-urlencoded'
		}
		
		try:
			request_data = {"search": lookup_search,
							  "exec_mode": 'oneshot',
							  "count": '0',
							  "rf": self.lookupfield,   # Required fields list
							  "namespace": namespace,
							  "output_mode": 'json'} 
			#logger.debug('Request data: %s', str(request_data))
			logger.debug('Search URL: %s', str(search_url))
			#logger.debug('Headers: %s', str(headers))
			
			payload = str.encode(urllib.parse.urlencode(request_data))
			json_data, result_code = request('POST', search_url, payload, headers)
			
			# Write the values from the lookup to lookup_list
			self.lookup_list = json.loads(json_data)['results']
			
			logger.info('Retrieved %d records from lookup %s', len(self.lookup_list), self.lookup)
			logger.debug('Response code: %s', result_code)
			#logger.debug('Response contents: %s', json_data)
		except BaseException as e:
			logger.error('Could not cache lookup %s: %s', self.lookup, repr(e))

		# Make a Pool of workers
		pool = ThreadPool(5)

		try:
			count = 0
			if len(self.lookup_list) > 0:
				logger.debug("Running ThreadPool")
				results = pool.map(self.get_distances, events)
				for result in results:
					yield result
					count += 1
			else:
				for event in events:
					yield event
					count += 1

		except BaseException as e:
			logger.error("Error: %s" % repr(e))
			results = {}

		duration_secs = round(time.time()-start_time)
		logger.info("Completed fuzzylookup search command for %s results in %s seconds.", str(count), str(duration_secs) )

	# Run this thread once for each event
	def get_distances(self, event):
		logger = setup_logging('fuzzylookup')
		start_time = time.time()
		
		# sf = search field / field from search results
		# Convert to Unicode (py3 compatible)
		event_field_value = str(event[self.searchfield].lower())
		if event_field_value is None or len(event_field_value) == 0:
			return event

		logger.debug('Calculating distances for %s', event_field_value)
		#logger.debug(event)
		# Iterate through lookupfield results and calculate get_distances
		best_match_string = None
		active_score = 100
		active_charmatch = 0
		best_score = 100
		best_charmatch = 0
		#best_sequencelen = 0
		#active_sequencelen = 0
		dynamic_matches = 0
		dynamic_match_list = []
		dynamic_filters = {}
		use_cache = True

		try:
			# See if we have a dynamic lookup filter (references event field values)
			if len(self.lookup_filters_dynamic) > 0:
				# For this event, calculate the dynamic lookup filters based on the data in the event
				# Using this feature dramatically speeds up searches by limiting the number of rows compared
				dynamic_filter_keys = []
				for s in self.lookup_filters_dynamic:
					try:
						# Look for dynamic variables in the provided filter ($xxxxx$)
						lookup_filter_value = s['value']
						match_list = re.findall(r'\$[^\$]+\$', lookup_filter_value)

						# For each match, replace instances of $xxxxxx$ with the field value from the event
						# Supports multiple event fields
						for group in match_list:
							v = group.strip('$')
							if v in list(event.keys()):
								lookup_filter_value = lookup_filter_value.replace(group, event[v])

						dynamic_filters[s['field']] = lookup_filter_value
					except BaseException as e:
						logger.error("Error building dynamic lookup filters: %s", repr(e))
					# We may have more than one filtered field per row. Account for that here.
					dynamic_filter_keys.append(s['field'] + "=" + lookup_filter_value)

				# Generate the key string so we can recall the same lookup rows later for more events
				# This is to have a shorter list to compare against
				if len(dynamic_filter_keys) > 0:
					#logger.debug(str(dynamic_filter_keys))
					dynamic_filter_keys.sort()
					dynamic_filters_key = '|'.join(dynamic_filter_keys)
					#logger.debug("dynamic_filters_key = " + dynamic_filters_key)

					if dynamic_filters_key in list(self.prepopulated_filter_lookupdata.keys()) and use_cache:
						logger.debug("Using prepopulated filter lookup data for " + dynamic_filters_key)
						comparison_list = self.prepopulated_filter_lookupdata[dynamic_filters_key]
						# Make sure we skip the filter comparison and go straight to Levenshtein 
						dynamic_filters = {}
					else:
						comparison_list = self.lookup_list
						#logger.debug("Cached dynamic filter results: " + str(len(list(self.prepopulated_filter_lookupdata.keys()))))

				else:
					logger.error("No dynamic filters matched for input: " + str(event))
					return event
			else:
				# No dynamic filters found. Use the raw lookup list.
				comparison_list = self.lookup_list
				dynamic_filters_key = None

			comparison_count = 0
			#logger.info('Finding shortest distance')
			for lookup_record in comparison_list:
				comparison_count += 1

				# We have a dynamic filter so we have to grab the field referenced from the event
				# Ex: Lookupfield2=\"*@$email_domain$\""
				# s['field'] = 'Lookupfield2'
				# s['value'] = "*@$email_domain$"
				filter_matched = True
				for filter_key, filter_value in list(dynamic_filters.items()):
					try:
						#dynamic_filter_list.append(lookup_filter_value)
						if filter_key in list(lookup_record.keys()):
							# Make sure the dynamic filter field matches the dynamic filter value
							# Prepare the text field to be compared against
							lookup_value = lookup_record[filter_key]
							# Use fnmatch to do a pure wildcard search between the lookup row value
							#  and the dynamic filter text from the event
							#logger.debug("Comparing %s to %s", lookup_value, lookup_filter_value)
							if fnmatch.fnmatch(lookup_value, filter_value):
								pass
							else:
								# If the record doesn't match, skip to the next lookup value (see below)
								filter_matched = False
						else:
							logger.debug("Lookup record skipped. Missing field %s: %s", s['field'], str(lookup_record))
							filter_matched = False

					except BaseException as e:
						logger.error("Error checking dynamic lookup filters: %s", repr(e))

				if filter_matched:
					dynamic_matches += 1
					# Use this match for caching lookup entries that match this dynamic filter
					dynamic_match_list.append(lookup_record)
				else:
					# Skip comparison
					continue

				# Produce a list of fields to output if we were not supplied one
				if len(self.output_aliases) == 0:
					for lookup_field in list(lookup_record.keys()):
						self.output_aliases[lookup_field] = lookup_field

				# Get the lookup field value
				lookup_value = lookup_record[self.lookupfield]

				# Convert to Unicode (Python 3 compatible version)
				sf_compare = str(event_field_value.lower())
				lf_compare = str(lookup_value.lower())
				try:
					# Apply the deletions and masking prior to comparisons being made
					if self.delete is not None:
						sf_compare = re.sub(self.delete, '', sf_compare)
						lf_compare = re.sub(self.delete, '', lf_compare)
					if self.mask is not None:
						sf_compare = re.sub(self.mask, '*', sf_compare)
						lf_compare = re.sub(self.mask, '*', lf_compare)

					#logger.debug("Comparing %s to %s", sf_compare, lf_compare)
					active_score = jf.levenshtein_distance(sf_compare, lf_compare)
					active_charmatch = matching_chars(sf_compare, lf_compare)
					#active_sequencelen = overlap_length(sf_compare, lf_compare)

					#logger.debug("Compared %s to %s to get result=%s/%s (score/overlap)", sf_compare, lf_compare, str(active_score), str(active_charmatch))
					# Get the result with the greatest 1:1 character overlap if the scores are identical
					#if active_score < best_score or (active_score == best_score and (active_charmatch > best_charmatch or active_sequencelen > best_sequencelen)):
					if active_score < best_score or (active_score == best_score and active_charmatch > best_charmatch):
						#logger.debug("New best score: %s/%s  result=%s/%s (score/overlap).  Was %s/%s/%s. Count=%s", sf_compare, lf_compare, str(active_score), str(active_charmatch), str(best_match_string), str(best_score), str(best_charmatch), str(comparison_count))
						best_match_string = lookup_value
						best_match_lookup_record = lookup_record
						best_score =  active_score
						best_charmatch = active_charmatch
						#best_sequencelen = active_sequencelen
						best_lf_compare = lf_compare
					elif active_score == best_score and active_charmatch == best_charmatch:
						if type(best_match_string) is list:
							best_match_string.append(lookup_value)
							best_match_lookup_record.append(lookup_record)
						else:
							best_match_string = [best_match_string, lookup_value]
							best_match_lookup_record = [best_match_lookup_record, lookup_record]
					#elif lf_compare == 'kevman*' or lf_compare == 'knmew**':
					#	logger.debug("DEBUGGING: %s/%s  result=%s/%s (score/overlap).  Best=%s/%s/%s. Count=%s", sf_compare, lf_compare, str(active_score), str(active_charmatch), str(best_match_string), str(best_score), str(best_charmatch), str(comparison_count))

				except TypeError as e:
					logger.error("Type Error: " + repr(e))
					raise Exception
				except BaseException as e:
					logger.error("Error comparing %s to list entry %s: %s", event_field_value, lookup_value, repr(e))

			if best_score < 100:
				# Calculate a metric for similarity based on fuzzy score and string character overlap count
				fuzzy_weight = 75
				charmatch_weight = 25
				#sequencelen_weight = 25
				max_length = max(len(sf_compare), len(best_lf_compare))
				fuzzy_metric = round((1-(float(best_score) / max_length)) * fuzzy_weight, 2) # inverted, best=0
				charmatch_metric = round((float(best_charmatch) / max_length) * charmatch_weight, 2)
				#sequencelen_metric = round((1-(float(best_sequencelen) / max_length)) * sequencelen_weight, 2)

				# Output the fuzzy metrics
				event[self.prefix + "fuzzy_score"] = best_score
				event[self.prefix + "fuzzy_charmatch"] = best_charmatch
				#event[self.prefix + "fuzzy_sequencelen"] = best_sequencelen
				event[self.prefix + "fuzzy_similarity"] = fuzzy_metric + charmatch_metric # + sequencelen_metric

				# Convert to a list (if not already a list) to simplify the next section
				if isinstance(best_match_lookup_record, list):
					pass
					# Get the one with the best consecutive character sequence
					#new_results = []
					#for record in best_match_lookup_record:
				else:
					best_match_lookup_record = [best_match_lookup_record]
			
				event[self.prefix + "fuzzy_match"] = best_match_string
				
				# Output the fields from the lookup entry/entries
				if len(self.output_aliases) > 0:
					logger.debug('output_aliases length: ' + str(len(self.output_aliases)))
					# Only write selected entries to the event. Aliases and field names are identical if no alias specified.
					for lookup_field, lookup_field_alias in list(self.output_aliases.items()):
						logger.debug(self.output_overwrite)
						#logger.debug(event[lookup_field])
						logger.debug(lookup_record[lookup_field])
						if (self.output_overwrite or event[lookup_field] is None) and lookup_record[lookup_field] is not None:
							# Loop through the "best matches" lookup entries
							lookup_field_entries = []
							for lookup_record in best_match_lookup_record:
								lookup_field_entries.append(lookup_record[lookup_field])
							event[self.prefix + lookup_field_alias] = lookup_field_entries

			# Cache the dynamic lookup list entries in case another event needs the same list
			# This dramatically speeds up processing for dynamic filters that match a large part of the lookup
			if dynamic_filters_key is not None and dynamic_match_list is not None and len(list(dynamic_filters.keys())) > 0:
				self.prepopulated_filter_lookupdata[dynamic_filters_key] = dynamic_match_list
				#logger.debug("prepopulated_filter_lookupdata count (child process) = " + str(len(list(self.prepopulated_filter_lookupdata.keys()))))

			duration_secs = round(time.time()-start_time)
			logger.debug("Done calculating distances for %s in %s seconds. Result: %s", event_field_value, str(duration_secs), best_match_string)
			if dynamic_filters_key is not None:
				logger.debug("Dynamic filter matches for %s: %s", dynamic_filters_key, dynamic_matches)
		except BaseException as e:
			logger.error("get_distances error: " + repr(e))
			tb = traceback.format_exc()
			logger.error(tb)
		return event

# Break this out since we're using multiprocessing
if __name__ == '__main__':
	dispatch(fuzzylookup, sys.argv, sys.stdin, sys.stdout, __name__)
