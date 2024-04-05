/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2017 Phusion Holding B.V.
 *
 *  "Passenger", "Phusion Passenger" and "Union Station" are registered
 *  trademarks of Phusion Holding B.V.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */
#ifndef _PASSENGER_APACHE2_MODULE_CONFIG_GENERAL_MANIFEST_GENERATION_H_
#define _PASSENGER_APACHE2_MODULE_CONFIG_GENERAL_MANIFEST_GENERATION_H_

#include <string>
#include <cstddef>
#include <string>
#include <boost/function.hpp>
#include <boost/json.hpp>

#include "../Config.h"
#include "../Utils.h"
#include <StaticString.h>
#include <FileTools/PathManip.h>

// The APR headers must come after the Passenger headers.
// See Hooks.cpp to learn why.
#include <httpd.h>
#include <http_config.h>
// In Apache < 2.4, this macro was necessary for core_dir_config and other structs
#define CORE_PRIVATE
#include <http_core.h>


extern "C" module AP_MODULE_DECLARE_DATA passenger_module;

#ifndef ap_get_core_module_config
	#define ap_get_core_module_config(s) ap_get_module_config(s, &core_module)
#endif


namespace Passenger {
namespace Apache2Module {

using namespace std;


class ConfigManifestGenerator {
private:
	json::value manifest;
	server_rec *serverRec;
	apr_pool_t *pool;

	void autoGenerated_generateConfigManifestForServerConfig();
	void autoGenerated_generateConfigManifestForDirConfig(server_rec *serverRec,
		core_server_config *csconf,core_dir_config *cdconf, DirConfig *pdconf,
		DirConfigContext context);
	void autoGenerated_setGlobalConfigDefaults();
	void autoGenerated_setAppConfigDefaults();
	void autoGenerated_setLocationConfigDefaults();

	void processDirConfig(server_rec *serverRec, core_server_config *csconf,
		core_dir_config *cdconf, DirConfig *pdconf, DirConfigContext context)
	{
		if (pdconf->getEnabled()) {
			autoGenerated_generateConfigManifestForDirConfig(
				serverRec, csconf, cdconf, pdconf, context);
		}
	}

	void findOrCreateAppAndLocOptionsContainers(server_rec *serverRec,
		core_server_config *csconf, core_dir_config *cdconf,
		DirConfig *pdconf, DirConfigContext context,
		json::value **appOptionsContainer, json::value **locOptionsContainer)
	{
		if (*appOptionsContainer != NULL && *locOptionsContainer != NULL) {
			return;
		}

		if (context == DCC_GLOBAL) {
			*appOptionsContainer = &manifest["default_application_configuration"];
			*locOptionsContainer = &manifest["default_location_configuration"];
		} else if (context == DCC_VHOST) {
			string appGroupName = inferLocConfAppGroupName(csconf, pdconf);
			json::value &appConfigContainer = findOrCreateAppConfigContainer(appGroupName);
			*appOptionsContainer = &appConfigContainer["options"];
			*locOptionsContainer = &appConfigContainer["default_location_configuration"];

			// Create a default value for PassengerAppGroupName and
			// PassengerAppRoot if we just created this config container
			if ((*appOptionsContainer)->empty()) {
				addOptionsContainerInferredDefaultStr(**appOptionsContainer,
					"PassengerAppGroupName",
					appGroupName);
				addOptionsContainerInferredDefaultStr(**appOptionsContainer,
					"PassengerAppRoot",
					inferDefaultAppRoot(csconf));
			}
		} else {
			// We are inside a <Directory> or <Location>
			string appGroupName = inferLocConfAppGroupName(csconf, pdconf);
			json::value &appConfigContainer = findOrCreateAppConfigContainer(appGroupName);
			json::value &locConfigContainer = findOrCreateLocConfigContainer(appConfigContainer,
				serverRec, cdconf, pdconf);
			*appOptionsContainer = &appConfigContainer["options"];
			*locOptionsContainer = &locConfigContainer["options"];
		}
	}

	string inferLocConfAppGroupName(core_server_config *csconf, DirConfig *pdconf) {
		if (pdconf->getAppGroupName().empty()) {
			string appRoot;
			StaticString appEnv;

			if (pdconf->getAppRoot().empty()) {
				// ap_document_root is already relativized against
				// the ServerRoot (see Apache server/core.c set_document_root())
				appRoot = csconf->ap_document_root + P_STATIC_STRING("/..");
			} else {
				appRoot = ap_server_root_relative(pool, pdconf->getAppRoot().c_str());
			}
			appRoot = absolutizePath(appRoot);

			if (pdconf->getAppEnv().empty()) {
				appEnv = P_STATIC_STRING(DEFAULT_APP_ENV);
			} else {
				appEnv = pdconf->getAppEnv();
			}

			return appRoot + " (" + appEnv + ")";
		} else {
			return pdconf->getAppGroupName();
		}
	}

	string inferDefaultAppRoot(core_server_config *csconf) {
		return absolutizePath(csconf->ap_document_root + P_STATIC_STRING("/.."));
	}

	json::value	&findOrCreateAppConfigContainer(const string &appGroupName) {
		json::value &result = manifest["application_configurations"][appGroupName];
		if (result.isNull()) {
			result["options"] = json::object;
			result["default_location_configuration"] = json::object;
			result["location_configurations"] = Json::arrayValue;
		}
		return result;
	}

	json::value &findOrCreateLocConfigContainer(json::value &appConfigContainer,
		server_rec *serverRec, core_dir_config *cdconf, DirConfig *pdconf)
	{
		json::value &locConfigsContainer = appConfigContainer["location_configurations"];
		json::value *locConfigContainer = findLocConfigContainer(
			locConfigsContainer, serverRec, cdconf, pdconf);
		if (locConfigContainer == NULL) {
			locConfigContainer = &createLocConfigContainer(locConfigsContainer,
				serverRec, cdconf, pdconf);
		}
		return *locConfigContainer;
	}

	json::value *findLocConfigContainer(json::value &locConfigsContainer,
		server_rec *serverRec, core_dir_config *cdconf, DirConfig *pdconf)
	{
		json::value::iterator it, end = locConfigsContainer.end();
		for (it = locConfigsContainer.begin(); it != end; it++) {
			json::value &locConfigContainer = *it;
			json::value &locationMatcherDoc = locConfigContainer["location_matcher"];
			string jsonLocationMatcherType = locationMatcherDoc["type"].asString();

			if (cdconf->r != NULL) {
				if (jsonLocationMatcherType != "regex") {
					continue;
				}
			} else {
				if (jsonLocationMatcherType != "prefix") {
					continue;
				}
			}

			string jsonLocationMatcherValue = locationMatcherDoc["value"].asString();
			if (jsonLocationMatcherValue != cdconf->d) {
				continue;
			}

			json::value &serverNamesDoc =
				locConfigContainer["web_server_virtual_host"]["server_names"];
			if (!matchesAnyServerNames(serverRec, serverNamesDoc)) {
				continue;
			}

			return &locConfigContainer;
		}

		return NULL;
	}

	json::value &createLocConfigContainer(json::value &locConfigsContainer,
		server_rec *serverRec, core_dir_config *cdconf, DirConfig *pdconf)
	{
		json::value vhostDoc;
		if (serverRec->defn_name) {
			vhostDoc["server_names"].append(serverRec->defn_name);
		} else {
			vhostDoc["server_names"].append("NOT_RECEIVED");
		}

		json::value locationMatcherDoc;
		locationMatcherDoc["value"] = cdconf->d;
		if (cdconf->r != NULL) {
			locationMatcherDoc["type"] = "regex";
		} else {
			locationMatcherDoc["type"] = "prefix";
		}

		json::value locConfigContainer;
		locConfigContainer["web_server_virtual_host"] = vhostDoc;
		locConfigContainer["location_matcher"] = locationMatcherDoc;
		locConfigContainer["options"] = json::object;
		return locConfigsContainer.append(locConfigContainer);
	}

	bool matchesAnyServerNames(server_rec *serverRec, const json::value &serverNamesDoc) {
		json::value::const_iterator it, end = serverNamesDoc.end();

		for (it = serverNamesDoc.begin(); it != end; it++) {
			// TODO: lowercase match
			if (it->asString() == serverRec->defn_name) {
				return true;
			}
		}

		return false;
	}

	json::value &findOrCreateOptionContainer(json::value &optionsContainer,
		const char *optionName, size_t optionNameLen)
	{
		json::value &result = optionsContainer[string(optionName, optionNameLen)];
		if (result.isNull()) {
			initOptionContainer(result);
		}
		return result;
	}

	void initOptionContainer(json::value &doc) {
		doc["value_hierarchy"] = Json::arrayValue;
	}

	json::value &addOptionContainerHierarchyMember(json::value &optionContainer,
		const StaticString &sourceFile, unsigned int sourceLine)
	{
		json::value hierarchyMember;
		hierarchyMember["source"]["type"] = "web-server-config";
		hierarchyMember["source"]["path"] = json::value(sourceFile.data(),
			sourceFile.data() + sourceFile.size());
		hierarchyMember["source"]["line"] = sourceLine;
		return optionContainer["value_hierarchy"].append(hierarchyMember);
	}

	void reverseValueHierarchies() {
		json::value &appConfigsContainer = manifest["application_configurations"];
		json::value::iterator it, end = appConfigsContainer.end();

		reverseValueHierarchiesInOptionsContainer(manifest["global_configuration"]);
		reverseValueHierarchiesInOptionsContainer(manifest["default_application_configuration"]);
		reverseValueHierarchiesInOptionsContainer(manifest["default_location_configuration"]);

		for (it = appConfigsContainer.begin(); it != end; it++) {
			json::value &appConfigContainer = *it;

			reverseValueHierarchiesInOptionsContainer(
				appConfigContainer["options"]);
			reverseValueHierarchiesInOptionsContainer(
				appConfigContainer["default_location_configuration"]);

			if (appConfigContainer.isMember("location_configurations")) {
				json::value &locationConfigsContainer = appConfigContainer["location_configurations"];
				json::value::iterator it2, end2 = locationConfigsContainer.end();

				for (it2 = locationConfigsContainer.begin(); it2 != end2; it2++) {
					json::value &locationConfigContainer = *it2;
					reverseValueHierarchiesInOptionsContainer(
						locationConfigContainer["options"]);
				}
			}
		}
	}

	void reverseValueHierarchiesInOptionsContainer(json::value &optionsContainer) {
		json::value::iterator it, end = optionsContainer.end();

		for (it = optionsContainer.begin(); it != end; it++) {
			json::value &optionContainer = *it;
			json::value &valueHierarchyDoc = optionContainer["value_hierarchy"];
			unsigned int len = valueHierarchyDoc.size();

			for (unsigned int i = 0; i < len / 2; i++) {
				valueHierarchyDoc[i].swap(valueHierarchyDoc[len - i - 1]);
			}
		}
	}

	void inheritApplicationValueHierarchies() {
		json::value &appConfigsContainer = manifest["application_configurations"];
		json::value &defaultAppConfigContainer = manifest["default_application_configuration"];
		json::value::iterator it, end = appConfigsContainer.end();

		/* Iterate through all 'application_configurations' objects */
		for (it = appConfigsContainer.begin(); it != end; it++) {
			json::value &appConfigContainer = *it;
			json::value::iterator it2, end2;

			/* Iterate through all its 'options' objects */
			json::value &optionsContainer = appConfigContainer["options"];
			end2 = optionsContainer.end();
			for (it2 = optionsContainer.begin(); it2 != end2; it2++) {
				/* For each option, inherit the value hierarchies
				 * from the 'default_application_configuration' object.
				 *
				 * Since the value hierarchy array is already in
				 * most-to-least-specific order, simply appending
				 * the 'default_application_configuration' hierarchy is
				 * enough.
				 */
				const char *optionNameEnd;
				const char *optionName = it2.memberName(&optionNameEnd);

				if (defaultAppConfigContainer.isMember(optionName, optionNameEnd)) {
					json::value &optionContainer = *it2;
					json::value &defaultAppConfig = defaultAppConfigContainer[optionName];
					json::value &valueHierarchyDoc = optionContainer["value_hierarchy"];
					json::value &valueHierarchyFromDefault = defaultAppConfig["value_hierarchy"];

					jsonAppendValues(valueHierarchyDoc, valueHierarchyFromDefault);
					maybeInheritStringArrayHierarchyValues(valueHierarchyDoc);
					maybeInheritStringKeyvalHierarchyValues(valueHierarchyDoc);
				}
			}

			/* Iterate through all 'default_application_configuration' options */
			end2 = defaultAppConfigContainer.end();
			for (it2 = defaultAppConfigContainer.begin(); it2 != end2; it2++) {
				/* For each default app config object, if there is no object in
				 * the current context's 'options' with the same name, then add
				 * it there.
				 */
				const char *optionNameEnd;
				const char *optionName = it2.memberName(&optionNameEnd);
				if (!optionsContainer.isMember(optionName, optionNameEnd)) {
					json::value &optionContainer = *it2;
					optionsContainer[optionName] = optionContainer;
				}
			}
		}
	}

	void maybeInheritStringArrayHierarchyValues(json::value &valueHierarchyDoc) {
		if (valueHierarchyDoc.empty()) {
		    return;
		}
		if (!valueHierarchyDoc[0]["value"].isArray()) {
		    return;
		}

		unsigned int len = valueHierarchyDoc.size();
		for (unsigned int i = len - 1; i >= 1; i--) {
			json::value &current = valueHierarchyDoc[i];
			json::value &next = valueHierarchyDoc[i - 1];

			json::value &currentValue = current["value"];
			json::value &nextValue = next["value"];

			json::value::iterator it, end = currentValue.end();
			for (it = currentValue.begin(); it != end; it++) {
				if (!jsonArrayContains(nextValue, *it)) {
					nextValue.append(*it);
				}
			}
		}
	}

	void maybeInheritStringKeyvalHierarchyValues(json::value &valueHierarchyDoc) {
		if (valueHierarchyDoc.empty()) {
		    return;
		}
		if (!valueHierarchyDoc[0]["value"].isObject()) {
		    return;
		}

		unsigned int len = valueHierarchyDoc.size();
		for (unsigned int i = len - 1; i >= 1; i--) {
			json::value &current = valueHierarchyDoc[i];
			json::value &next = valueHierarchyDoc[i - 1];

			json::value &currentValue = current["value"];
			json::value &nextValue = next["value"];

			json::value::iterator it, end = currentValue.end();
			for (it = currentValue.begin(); it != end; it++) {
				const char *nameEnd;
				const char *name = it.memberName(&nameEnd);

				if (!nextValue.isMember(name, nameEnd)) {
					nextValue[name] = *it;
				}
			}
		}
	}

	void inheritLocationValueHierarchies() {
		json::value &appConfigsContainer = manifest["application_configurations"];
		json::value &defaultLocConfigContainer = manifest["default_location_configuration"];
		json::value::iterator it, end = appConfigsContainer.end();

		/* Iterate through all 'application_configurations' objects */
		for (it = appConfigsContainer.begin(); it != end; it++) {
			json::value &appConfigContainer = *it;
			json::value::iterator it2, end2;

			/* Iterate through all its 'default_location_configuration' options */
			json::value &appDefaultLocationConfigs = appConfigContainer[
				"default_location_configuration"];
			end2 = appDefaultLocationConfigs.end();
			for (it2 = appDefaultLocationConfigs.begin(); it2 != end2; it2++) {
				/* For each option, inherit the value hierarchies
				 * from the top-level 'default_application_configuration' object.
				 *
				 * Since the value hierarchy array is already in
				 * most-to-least-specific order, simply appending
				 * the 'default_application_configuration' hierarchy is
				 * enough.
				 */
				const char *optionNameEnd;
				const char *optionName = it2.memberName(&optionNameEnd);

				if (defaultLocConfigContainer.isMember(optionName, optionNameEnd)) {
					json::value &optionContainer = *it2;
					json::value &defaultLocationConfig = defaultLocConfigContainer[optionName];
					json::value &valueHierarchyDoc = optionContainer["value_hierarchy"];
					json::value &valueHierarchyFromDefault = defaultLocationConfig["value_hierarchy"];

					jsonAppendValues(valueHierarchyDoc, valueHierarchyFromDefault);
					maybeInheritStringArrayHierarchyValues(valueHierarchyDoc);
					maybeInheritStringKeyvalHierarchyValues(valueHierarchyDoc);
				}
			}

			/* Iterate through all top-level 'default_location_configuration' options */
			end2 = defaultLocConfigContainer.end();
			for (it2 = defaultLocConfigContainer.begin(); it2 != end2; it2++) {
				/* For each default top-level 'default_location_configuration' option,
				 * if there is no object in the current context's 'default_application_configuration'
				 * with the same name, then add it there.
				 */
				const char *optionNameEnd;
				const char *optionName = it2.memberName(&optionNameEnd);
				if (!appDefaultLocationConfigs.isMember(optionName, optionNameEnd)) {
					appDefaultLocationConfigs[optionName] = *it2;
				}
			}

			/* Iterate through all its 'location_configurations' options */
			if (appConfigContainer.isMember("location_configurations")) {
				json::value &locationConfigsContainer = appConfigContainer["location_configurations"];
				end2 = locationConfigsContainer.end();

				for (it2 = locationConfigsContainer.begin(); it2 != end2; it2++) {
					json::value &locationContainer = *it2;
					json::value &optionsContainer = locationContainer["options"];
					json::value::iterator it3, end3 = optionsContainer.end();

					for (it3 = optionsContainer.begin(); it3 != end3; it3++) {
						/* For each option, inherit the value hierarchies
						 * from the 'default_location_configuration' belonging
						 * to the current app (which also contains the global
						 * location config defaults).
						 *
						 * Since the value hierarchy array is already in
						 * most-to-least-specific order, simply appending
						 * the 'default_location_configuration' hierarchy is
						 * enough.
						 */
						const char *optionNameEnd;
						const char *optionName = it3.memberName(&optionNameEnd);

						if (appDefaultLocationConfigs.isMember(optionName, optionNameEnd)) {
							json::value &optionContainer = *it3;
							json::value &defaultLocationConfig = appDefaultLocationConfigs[optionName];
							json::value &valueHierarchyDoc = optionContainer["value_hierarchy"];
							json::value &valueHierarchyFromDefault = defaultLocationConfig["value_hierarchy"];

							jsonAppendValues(valueHierarchyDoc, valueHierarchyFromDefault);
							maybeInheritStringArrayHierarchyValues(valueHierarchyDoc);
							maybeInheritStringKeyvalHierarchyValues(valueHierarchyDoc);
						}
					}
				}
			}
		}
	}

	void addOptionsContainerDynamicDefault(json::value &optionsContainer,
		const char *optionName, const StaticString &desc)
	{
		json::value &optionContainer = optionsContainer[optionName];
		if (optionContainer.isNull()) {
			initOptionContainer(optionContainer);
		}

		json::value hierarchyMember;
		hierarchyMember["source"]["type"] = "dynamic-default-description";
		hierarchyMember["value"] = json::value(desc.data(),
			desc.data() + desc.size());

		optionContainer["value_hierarchy"].append(hierarchyMember);
	}

	json::value &addOptionsContainerDefault(json::value &optionsContainer,
		const char *defaultType, const char *optionName)
	{
		json::value &optionContainer = optionsContainer[optionName];
		if (optionContainer.isNull()) {
			initOptionContainer(optionContainer);
		}

		json::value hierarchyMember;
		hierarchyMember["source"]["type"] = defaultType;

		return optionContainer["value_hierarchy"].append(hierarchyMember);
	}

	void addOptionsContainerStaticDefaultStr(json::value &optionsContainer,
		const char *optionName, const StaticString &value)
	{
		json::value &hierarchyMember = addOptionsContainerDefault(
			optionsContainer, "default", optionName);
		hierarchyMember["value"] = json::value(value.data(),
			value.data() + value.size());
	}

	void addOptionsContainerStaticDefaultInt(json::value &optionsContainer,
		const char *optionName, int value)
	{
		json::value &hierarchyMember = addOptionsContainerDefault(
			optionsContainer, "default", optionName);
		hierarchyMember["value"] = value;
	}

	void addOptionsContainerStaticDefaultBool(json::value &optionsContainer,
		const char *optionName, bool value)
	{
		json::value &hierarchyMember = addOptionsContainerDefault(
			optionsContainer, "default", optionName);
		hierarchyMember["value"] = value;
	}

	void addOptionsContainerInferredDefaultStr(json::value &optionsContainer,
		const char *optionName, const StaticString &value)
	{
		json::value &hierarchyMember = addOptionsContainerDefault(
			optionsContainer, "inferred-default", optionName);
		hierarchyMember["value"] = json::value(value.data(),
			value.data() + value.size());
	}

	void jsonAppendValues(json::value &doc, const json::value &doc2) {
		json::value::const_iterator it, end = doc2.end();

		for (it = doc2.begin(); it != end; it++) {
			doc.append(*it);
		}
	}

	bool jsonArrayContains(const json::value &doc, const json::value &elem) {
		json::value::const_iterator it, end = doc.end();
		for (it = doc.begin(); it != end; it++) {
			if (*it == elem) {
				return true;
			}
		}

		return false;
	}

public:
	ConfigManifestGenerator(server_rec *_serverRec, apr_pool_t *_pool)
		: serverRec(_serverRec),
		  pool(_pool)
	{
		manifest["global_configuration"] = json::object;
		manifest["default_application_configuration"] = json::object;
		manifest["default_location_configuration"] = json::object;
		manifest["application_configurations"] = json::object;
	}

	const json::value &execute() {
		autoGenerated_generateConfigManifestForServerConfig();
		traverseAllDirConfigs(serverRec, pool,
			boost::bind<void>(&ConfigManifestGenerator::processDirConfig, this,
				boost::placeholders::_1, boost::placeholders::_2,
				boost::placeholders::_3, boost::placeholders::_4,
				boost::placeholders::_5));

		reverseValueHierarchies();
		autoGenerated_setGlobalConfigDefaults();
		autoGenerated_setAppConfigDefaults();
		autoGenerated_setLocationConfigDefaults();
		inheritApplicationValueHierarchies();
		inheritLocationValueHierarchies();

		return manifest;
	}
};


} // namespace Apache2Module
} // namespace Passenger

#include "../ServerConfig/AutoGeneratedManifestGeneration.cpp"
#include "../DirConfig/AutoGeneratedManifestGeneration.cpp"
#include "AutoGeneratedManifestDefaultsInitialization.cpp"

#endif /* _PASSENGER_APACHE2_MODULE_CONFIG_GENERAL_MANIFEST_GENERATION_H_ */
