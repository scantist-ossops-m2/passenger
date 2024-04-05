/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2017-2018 Phusion Holding B.V.
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
#ifndef _PASSENGER_ADMIN_PANEL_CONNECTOR_H_
#define _PASSENGER_ADMIN_PANEL_CONNECTOR_H_

#include <sys/wait.h>
#include <sstream>
#include <unistd.h>

#include <boost/scoped_ptr.hpp>
#include <boost/json.hpp>
#include <boost/thread.hpp>
#include <boost/bind/bind.hpp>
#include <boost/foreach.hpp>

#include <limits>
#include <string>
#include <vector>

#include <Constants.h>
#include <WebSocketCommandReverseServer.h>
#include <InstanceDirectory.h>
#include <ConfigKit/SchemaUtils.h>
#include <Core/ApplicationPool/Pool.h>
#include <Core/Controller.h>
#include <ProcessManagement/Ruby.h>
#include <FileTools/FileManip.h>
#include <JsonTools/JsonUtils.h>
#include <SystemTools/UserDatabase.h>
#include <Utils.h>
#include <StrIntTools/StrIntUtils.h>
#include <IOTools/IOUtils.h>
#include <Utils/AsyncSignalSafeUtils.h>
#include <LoggingKit/Context.h>

namespace Passenger {
namespace Core {

using namespace std;
using namespace oxt;
namespace ASSU = AsyncSignalSafeUtils;

class AdminPanelConnector {
public:
	/**
	 * BEGIN ConfigKit schema: Passenger::Core::AdminPanelConnector::Schema
	 * (do not edit: following text is automatically generated
	 * by 'rake configkit_schemas_inline_comments')
	 *
	 *   auth_type                   string    -          default("basic")
	 *   close_timeout               float     -          default(10.0)
	 *   connect_timeout             float     -          default(30.0)
	 *   data_debug                  boolean   -          default(false)
	 *   instance_dir                string    -          read_only
	 *   integration_mode            string    -          default("standalone")
	 *   log_prefix                  string    -          -
	 *   password                    string    -          secret
	 *   password_file               string    -          -
	 *   ping_interval               float     -          default(30.0)
	 *   ping_timeout                float     -          default(30.0)
	 *   proxy_password              string    -          secret
	 *   proxy_timeout               float     -          default(30.0)
	 *   proxy_url                   string    -          -
	 *   proxy_username              string    -          -
	 *   reconnect_timeout           float     -          default(5.0)
	 *   ruby                        string    -          default("ruby")
	 *   standalone_engine           string    -          default
	 *   url                         string    required   -
	 *   username                    string    -          -
	 *   web_server_module_version   string    -          read_only
	 *   web_server_version          string    -          read_only
	 *   websocketpp_debug_access    boolean   -          default(false)
	 *   websocketpp_debug_error     boolean   -          default(false)
	 *
	 * END
	 */
	struct Schema: public WebSocketCommandReverseServer::Schema {
		Schema()
			: WebSocketCommandReverseServer::Schema(false)
		{
			using namespace ConfigKit;

			add("integration_mode", STRING_TYPE, OPTIONAL, DEFAULT_INTEGRATION_MODE);
			addWithDynamicDefault("standalone_engine", STRING_TYPE, OPTIONAL,
				ConfigKit::getDefaultStandaloneEngine);
			add("instance_dir", STRING_TYPE, OPTIONAL | READ_ONLY);
			add("web_server_version", STRING_TYPE, OPTIONAL | READ_ONLY);
			add("web_server_module_version", STRING_TYPE, OPTIONAL | READ_ONLY);
			add("ruby", STRING_TYPE, OPTIONAL, "ruby");

			addValidator(ConfigKit::validateIntegrationMode);
			addValidator(ConfigKit::validateStandaloneEngine);

			finalize();
		}
	};

	typedef WebSocketCommandReverseServer::ConfigChangeRequest ConfigChangeRequest;

	typedef WebSocketCommandReverseServer::ConnectionPtr ConnectionPtr;
	typedef WebSocketCommandReverseServer::MessagePtr MessagePtr;
	typedef boost::function<json::value (void)> ConfigGetter;
	typedef vector<Controller*> Controllers;

private:
	WebSocketCommandReverseServer server;
	dynamic_thread_group threads;
	json::object globalPropertiesFromInstanceDir;

	bool onMessage(WebSocketCommandReverseServer *server,
		const ConnectionPtr &conn, const MessagePtr &msg)
	{
		json::object doc;

		try {
			doc = parseAndBasicValidateMessageAsJSON(msg->get_payload()).get_object();
		} catch (const RuntimeException &e) {
			json::object reply;
			reply["result"] = "error";
			reply["request_id"] = doc["request_id"];
			reply["data"].at("message") = e.what();
			sendJsonReply(conn, reply);
			return true;
		}

		if (doc["action"] == "get") {
			return onGetMessage(conn, doc);
		} else {
			return onUnknownMessageAction(conn, doc);
		}
	}


	bool onGetMessage(const ConnectionPtr &conn, const json::value &doc) {
		const json::string resource = doc.at("resource").as_string();

		if (resource == "server_properties") {
			return onGetServerProperties(conn, doc);
		} else if (resource == "global_properties") {
			return onGetGlobalProperties(conn, doc);
		} else if (resource == "global_configuration") {
			return onGetGlobalConfiguration(conn, doc);
		} else if (resource == "global_statistics") {
			return onGetGlobalStatistics(conn, doc);
		} else if (resource == "application_properties") {
			return onGetApplicationProperties(conn, doc);
		} else if (resource == "application_configuration") {
			return onGetApplicationConfig(conn, doc);
		} else if (resource == "application_logs") {
			return onGetApplicationLogs(conn, doc);
		} else {
			return onUnknownResource(conn, doc);
		}
	}

	bool onGetServerProperties(const ConnectionPtr &conn, const json::value &doc) {
		threads.create_thread(
			boost::bind(&AdminPanelConnector::onGetServerPropertiesBgJob, this,
						conn, doc, jsonValueToString(server.getConfig()["ruby"])),
			"AdminPanelCommandServer: get_server_properties background job",
			128 * 1024);
		return false;
	}

	void onGetServerPropertiesBgJob(const ConnectionPtr &conn, const json::value &doc,
		const string &ruby)
	{
		vector<string> args;
		args.push_back("passenger-config");
		args.push_back("system-properties");

		int status = 0;
		SubprocessOutput output;
		try {
			runInternalRubyTool(*resourceLocator, ruby, args, &status, &output);
		} catch (const std::exception &e) {
			server.getIoService().post(boost::bind(
				&AdminPanelConnector::onGetServerPropertiesDone, this,
				conn, doc, string(), -1, e.what()
			));
			return;
		}

		server.getIoService().post(boost::bind(
			&AdminPanelConnector::onGetServerPropertiesDone, this,
			conn, doc, output.data, status, string()
		));
	}

	void onGetServerPropertiesDone(const ConnectionPtr &conn, const json::value &doc,
		const string output, int status, const string &error)
	{
		json::object reply;
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		reply["request_id"] = doc.at("request_id");
		if (error.empty()) {
			if (status == 0 || status == -1) {
				if (output.empty()) {
					reply["result"] = "error";
					reply_data["message"] = "Error parsing internal helper tool output";
					P_ERROR(getLogPrefix() << "Error parsing internal helper tool output.\n" <<
							"Raw data: \"\"");
				} else {
					error_code ec;
					json::value dataDoc = json::parse(output, ec);
					if (!ec) {
						reply["result"] = "ok";
						reply_data = dataDoc.get_object();
					} else {
						reply["result"] = "error";
						reply_data["message"] = "Error parsing internal helper tool output";
						P_ERROR(getLogPrefix() << "Error parsing internal helper tool output.\n" <<
								"Error: " << ec.message() << "\n"
								"Raw data: \"" << cEscapeString(output) << "\"");
					}
				}
			} else {
				int exitStatus = WEXITSTATUS(status);
				reply["result"] = "error";
				reply_data["message"] = "Internal helper tool exited with status "
					+ toString(exitStatus);
				P_ERROR(getLogPrefix() << "Internal helper tool exited with status "
					<< exitStatus << ". Raw output: \"" << cEscapeString(output) << "\"");
			}
		} else {
			reply["result"] = "error";
			reply_data["message"] = error;
		}
		sendJsonReply(conn, reply);
		server.doneReplying(conn);
	}

	bool onGetGlobalProperties(const ConnectionPtr &conn, const json::value &doc) {
		const ConfigKit::Store &config = server.getConfig();
		json::object reply, data;
		reply["result"] = "ok";
		reply["request_id"] = doc.at("request_id");

		data = globalPropertiesFromInstanceDir;
		data["version"] = PASSENGER_VERSION;
		data["core_pid"] = uint64_t(getpid());

		json::string integrationMode = config["integration_mode"].as_string();
		data["integration_mode"] = json::object();
		json::object &data_integration_mode = data["integration_mode"].get_object();
		data_integration_mode["name"] = integrationMode;
		if (!config["web_server_module_version"].is_null()) {
			data_integration_mode["web_server_module_version"] = config["web_server_module_version"];
		}
		if (integrationMode == "standalone") {
			data_integration_mode["standalone_engine"] = config["standalone_engine"];
		}
		if (!config["web_server_version"].is_null()) {
			data_integration_mode["web_server_version"] = config["web_server_version"];
		}

		data["originally_packaged"] = resourceLocator->isOriginallyPackaged();
		if (!resourceLocator->isOriginallyPackaged()) {
			data["packaging_method"] = resourceLocator->getPackagingMethod();
		}

		reply["data"] = data;
		sendJsonReply(conn, reply);
		return true;
	}

	bool onGetGlobalConfiguration(const ConnectionPtr &conn, const json::value &doc) {
		threads.create_thread(
			boost::bind(&AdminPanelConnector::onGetGlobalConfigurationBgJob, this,
				conn, doc),
			"AdminPanelCommandServer: get_global_config background job",
			128 * 1024);
		return false;
	}

	void onGetGlobalConfigurationBgJob(const ConnectionPtr &conn, const json::value &input) {
		json::value &&globalConfig = configGetter().at_pointer("/config_manifest/effective_value/global_configuration");
		server.getIoService().post(boost::bind(
			&AdminPanelConnector::onGetGlobalConfigDone, this,
			conn, input, globalConfig
		));
	}

	void onGetGlobalConfigDone(const ConnectionPtr &conn, const json::value &input,
		json::value config)
	{
		json::object reply;

		reply["result"] = "ok";
		reply["request_id"] = input.at("request_id");
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		reply_data["options"] = config;

		sendJsonReply(conn, reply);
		server.doneReplying(conn);
	}

	bool onGetGlobalStatistics(const ConnectionPtr &conn, const json::value &doc) {
		json::object reply;
		reply["result"] = "ok";
		reply["request_id"] = doc.at("request_id");
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		reply_data["message"] = json::array();
		json::array &reply_data_message = reply_data["message"].get_array();

		for (unsigned int i = 0; i < controllers.size(); i++) {
			reply_data_message.push_back(controllers[i]->inspectStateAsJson());
		}

		sendJsonReply(conn, reply);
		return true;
	}

	bool onGetApplicationProperties(const ConnectionPtr &conn, const json::value &vdoc) {
		ConfigKit::Schema argumentsSchema =
			ApplicationPool2::Pool::ToJsonOptions::createSchema();
		json::object args, reply;
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		const json::object &doc = vdoc.get_object();
		ApplicationPool2::Pool::ToJsonOptions inspectOptions =
			ApplicationPool2::Pool::ToJsonOptions::makeAuthorized();

		if (doc.contains("arguments")) {
			ConfigKit::Store store(argumentsSchema);
			vector<ConfigKit::Error> errors;

			if (store.update(doc.at("arguments"), errors)) {
				inspectOptions.set(store.inspectEffectiveValues());
			} else {
				reply["result"] = "error";
				reply["request_id"] = doc.at("request_id");
				reply_data["message"] = "Invalid arguments: " +
					ConfigKit::toString(errors);
				sendJsonReply(conn, reply);
				return true;
			}
		}

		reply["result"] = "ok";
		reply["request_id"] = doc.at("request_id");
		reply_data["applications"] = appPool->inspectPropertiesInAdminPanelFormat(
			inspectOptions);
		sendJsonReply(conn, reply);
		return true;
	}

	static void modifyEnvironmentVariables(json::value &option) {
		json::array::iterator it;
		for (it = option.get_array().begin(); it != option.get_array().end(); it++) {
			json::object &suboption = it->get_object();
			suboption["value"] = json::serialize(suboption["value"]);
		}
	}

	bool onGetApplicationConfig(const ConnectionPtr &conn, const json::value &vdoc) {
		error_code ec;
		json::value &&appConfigsContainer = configGetter().at_pointer("/config_manifest/effective_value/application_configurations");
		json::value appConfigsContainerOutput;
		json::object reply;
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		const json::object &doc = vdoc.get_object();

		if (doc.contains("arguments")) {
			ConfigKit::Schema argumentsSchema =
				ApplicationPool2::Pool::ToJsonOptions::createSchema();
			ConfigKit::Store store(argumentsSchema);
			vector<ConfigKit::Error> errors;

			if (!store.update(doc.at("arguments"), errors)) {
				reply["result"] = "error";
				reply["request_id"] = doc.at("request_id");
				reply_data["message"] = "Invalid arguments: " +
					ConfigKit::toString(errors);
				sendJsonReply(conn, reply);
				return true;
			}

			json::value allowedApplicationIds =
				store.inspectEffectiveValues()["application_ids"];
			if (allowedApplicationIds.is_null()) {
				appConfigsContainerOutput = appConfigsContainer;
			} else {
				appConfigsContainerOutput = filterJsonObject(
					appConfigsContainer.get_object(),
					allowedApplicationIds.get_array());
			}
		} else {
			appConfigsContainerOutput = appConfigsContainer;
		}

		reply["result"] = "ok";
		reply["request_id"] = doc.at("request_id");
		reply_data["options"] = appConfigsContainerOutput;
		sendJsonReply(conn, reply);
		return true;
	}

	void addWatchedFiles() {
		json::value &&vappConfigs = configGetter().at_pointer("/config_manifest/effective_value/application_configurations");

		// As a hack, we look up the watched files config (passenger monitor log file) in the manifest. The manifest
		// is meant for users, which means that key names depend on the integration mode. In the future when
		// component configuration more routed through ConfigKit we can get rid of the hack.
		json::string integrationMode = server.getConfig()["integration_mode"].as_string();
		string passengerMonitorLogFile;
		string passengerAppRoot;
		if (integrationMode == "apache") {
			passengerMonitorLogFile = "PassengerMonitorLogFile";
			passengerAppRoot = "PassengerAppRoot";
		} else {
			passengerMonitorLogFile = "passenger_monitor_log_file";
			passengerAppRoot = "passenger_app_root";
			// TODO: this probably doesn't give any results with the builtin engine (not supported in other places either)
		}

		json::object &appConfigs = vappConfigs.get_object();
		json::object::const_iterator it, end = appConfigs.end();
		for (it=appConfigs.begin(); it != end; it++) {
			HashedStaticString key = it->key();
			json::value files = it->value().at_pointer("/options/" + passengerMonitorLogFile + "/value_hierarchy/0/value");
			json::string appRoot = it->value().at_pointer("/options/" + passengerAppRoot + "/value_hierarchy/0/value").get_string();

			pair<uid_t, gid_t> ids;
			try {
				ids = appPool->getGroupRunUidAndGids(key);
			} catch (const RuntimeException &) {
				files = json::value(nullptr);
			}
			if (!files.is_null()) {
				string usernameOrUid = lookupSystemUsernameByUid(ids.first, true);

				foreach (json::value file, files.get_array()) {
					json::string f = file.as_string();
					string maxLines = toString(LOG_MONITORING_MAX_LINES);
					Pipe pipe = createPipe(__FILE__, __LINE__);
					string agentExe = resourceLocator->findSupportBinary(AGENT_EXE);
					vector<const char *> execArgs;

					execArgs.push_back(agentExe.c_str());
					execArgs.push_back("exec-helper");
					if (geteuid() == 0) {
						execArgs.push_back("--user");
						execArgs.push_back(usernameOrUid.c_str());
					}
					execArgs.push_back("tail");
					execArgs.push_back("-n");
					execArgs.push_back(maxLines.c_str());
					execArgs.push_back(f.c_str());
					execArgs.push_back(NULL);

					pid_t pid = syscalls::fork();

					if (pid == -1) {
						int e = errno;
						throw SystemException("Cannot fork a new process", e);
					} else if (pid == 0) {
						chdir(appRoot.c_str());

						dup2(pipe.second, STDOUT_FILENO);
						pipe.first.close();
						pipe.second.close();
						closeAllFileDescriptors(2);

						execvp(execArgs[0], const_cast<char * const *>(&execArgs[0]));

						int e = errno;
						char buf[256];
						char *pos = buf;
						const char *end = pos + 256;

						pos = ASSU::appendData(pos, end, "Cannot execute \"");
						pos = ASSU::appendData(pos, end, agentExe.c_str());
						pos = ASSU::appendData(pos, end, "\": ");
						pos = ASSU::appendData(pos, end, strerror(e));
						pos = ASSU::appendData(pos, end, " (errno=");
						pos = ASSU::appendInteger<int, 10>(pos, end, e);
						pos = ASSU::appendData(pos, end, ")\n");
						ASSU::writeNoWarn(STDERR_FILENO, buf, pos - buf);
						_exit(1);
					} else {
						pipe.second.close();
						string out = readAll(pipe.first,
							std::numeric_limits<size_t>::max()).first;
						LoggingKit::context->saveMonitoredFileLog(key, f.c_str(), f.size(),
							out.data(), out.size());
						pipe.first.close();
						syscalls::waitpid(pid, NULL, 0);
					}
				}
			}
		}
	}

	bool onGetApplicationLogs(const ConnectionPtr &conn, const json::value &doc) {
		json::object reply;
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		reply["result"] = "ok";
		reply["request_id"] = doc.at("request_id");

		addWatchedFiles();

		reply_data["logs"] = LoggingKit::context->convertLog();
		sendJsonReply(conn, reply);
		return true;
	}

	bool onUnknownResource(const ConnectionPtr &conn, const json::value &doc) {
		json::object reply;
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		reply["result"] = "error";
		reply["request_id"] = doc.at("request_id");
		reply_data["message"] = "Unknown resource '" + getJsonStringField(doc, "resource") + "'";
		sendJsonReply(conn, reply);
		return true;
	}

	bool onUnknownMessageAction(const ConnectionPtr &conn, const json::value &doc) {
		json::object reply;
		reply["data"] = json::object();
		json::object &reply_data = reply["data"].get_object();
		reply["result"] = "error";
		reply["request_id"] = doc.at("request_id");
		reply_data["message"] = "Unknown action '" + getJsonStringField(doc,"action") + "'";
		sendJsonReply(conn, reply);
		return true;
	}


	json::value parseAndBasicValidateMessageAsJSON(const string &msg) const {
		error_code ec;
		json::value vdoc = json::parse(msg, ec);

		if (ec) {
			throw RuntimeException("Error parsing command JSON document: "
				+ ec.message());
		}

		if (!vdoc.is_object()) {
			throw RuntimeException("Invalid command JSON document: must be an object");
		}
		json::object &doc = vdoc.get_object();
		if (!doc.contains("action")) {
			throw RuntimeException("Invalid command JSON document: missing 'action' key");
		}
		if (!doc["action"].is_string()) {
			throw RuntimeException("Invalid command JSON document: the 'action' key must be a string");
		}
		if (!doc.contains("request_id")) {
			throw RuntimeException("Invalid command JSON document: missing 'request_id' key");
		}
		if (!doc.contains("resource")) {
			throw RuntimeException("Invalid command JSON document: missing 'resource' key");
		}
		if (!doc["resource"].is_string()) {
			throw RuntimeException("Invalid command JSON document: the 'resource' key must be a string");
		}
		if (doc.contains("arguments") && !doc["arguments"].is_object()) {
			throw RuntimeException("Invalid command JSON document: the 'arguments' key, when present, must be an object");
		}

		return doc;
	}

	void sendJsonReply(const ConnectionPtr &conn, const json::value &doc) {
		string str = json::serialize(doc);
		WCRS_DEBUG_FRAME(&server, "Replying with:", str);
		conn->send(str);
	}

	void readInstanceDirProperties(const string &instanceDir) {
		error_code ec;
		json::value doc = json::parse(unsafeReadFile(instanceDir + "/properties.json"), ec);

		if (ec) {
			throw RuntimeException("Cannot parse " + instanceDir + "/properties.json: "
				+ ec.message());
		}

		globalPropertiesFromInstanceDir["instance_id"] = doc.at("instance_id");
		globalPropertiesFromInstanceDir["watchdog_pid"] = doc.at("watchdog_pid");
	}

	json::value filterJsonObject(const json::object &object,
		const json::array &allowedKeys) const
	{
		json::array::const_iterator it, end = allowedKeys.end();
		json::object result;

		for (it = allowedKeys.begin(); it != end; it++) {
			if (object.contains(it->as_string())) {
				result[it->as_string()] = object.at(it->as_string());
			}
		}

		return result;
	}

	void initializePropertiesWithoutInstanceDir() {
		globalPropertiesFromInstanceDir["instance_id"] =
			InstanceDirectory::generateInstanceId();
	}

	string getLogPrefix() const {
		return jsonValueToString(server.getConfig()["log_prefix"]);
	}

	WebSocketCommandReverseServer::MessageHandler createMessageFunctor() {
		return boost::bind(&AdminPanelConnector::onMessage, this,
			boost::placeholders::_1, boost::placeholders::_2,
			boost::placeholders::_3);
	}

public:
	/******* Dependencies *******/

	ResourceLocator *resourceLocator;
	ApplicationPool2::PoolPtr appPool;
	ConfigGetter configGetter;
	Controllers controllers;


	AdminPanelConnector(const Schema &schema, const json::value &config,
		const ConfigKit::Translator &translator = ConfigKit::DummyTranslator())
		: server(schema, createMessageFunctor(), config, translator),
		  resourceLocator(NULL)
	{
		if (config.get_object().contains("instance_dir") &&
			config.at("instance_dir").is_string() &&
			!config.at("instance_dir").get_string().empty()) {
			readInstanceDirProperties(getJsonStringField(config,"instance_dir"));
		} else {
			initializePropertiesWithoutInstanceDir();
		}
	}

	void initialize() {
		if (resourceLocator == NULL) {
			throw RuntimeException("resourceLocator must be non-NULL");
		}
		if (appPool == NULL) {
			throw RuntimeException("appPool must be non-NULL");
		}
		if (configGetter.empty()) {
			throw RuntimeException("configGetter must be non-NULL");
		}
		server.initialize();
	}

	void run() {
		server.run();
	}

	void asyncPrepareConfigChange(const json::value &updates,
		ConfigChangeRequest &req,
		const ConfigKit::CallbackTypes<WebSocketCommandReverseServer>::PrepareConfigChange &callback)
	{
		server.asyncPrepareConfigChange(updates, req, callback);
	}

	void asyncCommitConfigChange(ConfigChangeRequest &req,
		const ConfigKit::CallbackTypes<WebSocketCommandReverseServer>::CommitConfigChange &callback)
		BOOST_NOEXCEPT_OR_NOTHROW
	{
		server.asyncCommitConfigChange(req, callback);
	}

	void asyncShutdown(const WebSocketCommandReverseServer::Callback &callback
		= WebSocketCommandReverseServer::Callback())
	{
		server.asyncShutdown(callback);
	}
};

} // namespace Core
} // namespace Passenger

#endif /* _PASSENGER_ADMIN_PANEL_CONNECTOR_H_ */
