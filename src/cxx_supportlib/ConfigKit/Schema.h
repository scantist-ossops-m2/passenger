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
#ifndef _PASSENGER_CONFIG_KIT_SCHEMA_H_
#define _PASSENGER_CONFIG_KIT_SCHEMA_H_

#include <boost/bind/bind.hpp>
#include <boost/container/vector.hpp>
#include <string>
#include <cassert>

#include <oxt/backtrace.hpp>
#include <boost/json.hpp>

#include <Exceptions.h>
#include <LoggingKit/LoggingKit.h>
#include <ConfigKit/Common.h>
#include <ConfigKit/DummyTranslator.h>
#include <ConfigKit/Utils.h>
#include <DataStructures/StringKeyTable.h>
#include <StrIntTools/StrIntUtils.h>

namespace Passenger {
namespace ConfigKit {

using namespace std;


/**
 * Represents a configuration schema. See the ConfigKit README for a description.
 *
 * Schema is thread-safe after finalization because it becomes immutable.
 */
class Schema {
public:
	struct Entry {
		Type type;
		Flags flags;
		ValueGetter defaultValueGetter;
		ValueFilter inspectFilter;
		// Can only be non-NULL when type == ARRAY_TYPE or OBJECT_TYPE.
		const Schema *nestedSchema;

		Entry()
			: type(UNKNOWN_TYPE),
			  flags(OPTIONAL),
			  nestedSchema(NULL)
			{ }

		Entry(Type _type, Flags _flags, const ValueGetter &_defaultValueGetter,
			const ValueFilter &_inspectFilter, const Schema *_nestedSchema = NULL)
			: type(_type),
			  flags(_flags),
			  defaultValueGetter(_defaultValueGetter),
			  inspectFilter(_inspectFilter),
			  nestedSchema(_nestedSchema)
			{ }

		bool tryTypecastValue(const json::value &val, json::value &result) const {
			if (val.is_null()) {
				result.emplace_null();
				return true;
			}

			switch (type) {
			case STRING_TYPE:
				if (val.is_string()) {
					result = val.get_string();
					return true;
				} else {
					return false;
				}
			case INT_TYPE:
				if (val.is_int64()) {
					result = val.get_int64();
					return true;
				} else {
					return false;
				}
			case UINT_TYPE:
				if (val.is_uint64()) {
					result = val.get_uint64();
					return true;
				} else {
					return false;
				}
			case FLOAT_TYPE:
				if (val.is_double()) {
					result = val.get_double();
					return true;
				} else {
					return false;
				}
			case BOOL_TYPE:
				if (val.is_bool()) {
					result = val.get_bool();
					return true;
				} else {
					return false;
				}
			case ARRAY_TYPE:
			case OBJECT_TYPE: {
				json::kind targetType;
				if (type == ARRAY_TYPE) {
					targetType = json::kind::array;
				} else {
					targetType = json::kind::object;
				}
				if (val.kind() == targetType) {
					if (nestedSchema != NULL) {
						return tryTypecastArrayOrObjectValueWithNestedSchema(val,
							result, "user_value");
					} else {
						result = val;
						return true;
					}
				} else {
					return false;
				}
			}
			default:
				result = val;
				return true;
			}
		}

		bool tryTypecastArrayOrObjectValueWithNestedSchema(const json::value &val,
			json::value &result, const char *userOrEffectiveValue) const;

		json::object inspect() const {
			json::object result;
			inspect(result);
			return result;
		}

		void inspect(json::object &doc) const {
			doc.insert_or_assign("type", getTypeString(type).data());
			if (flags & REQUIRED) {
				doc.insert_or_assign("required", true);
			}
			if (flags & READ_ONLY) {
				doc.insert_or_assign("read_only", true);
			}
			if (flags & SECRET) {
				doc.insert_or_assign("secret", true);
			}
			if (defaultValueGetter) {
				if (flags & _DYNAMIC_DEFAULT_VALUE) {
					doc.insert_or_assign("has_default_value", "dynamic");
				} else {
					doc.insert_or_assign("has_default_value", "static");
					doc.insert_or_assign("default_value", Schema::getStaticDefaultValue(*this));
				}
			}
			if (nestedSchema != NULL) {
				doc.insert_or_assign("nested_schema", nestedSchema->inspect());
			}
		}
	};

	class EntryBuilder {
	private:
		Entry *entry;

	public:
		EntryBuilder(Entry &_entry)
			: entry(&_entry)
			{ }

		EntryBuilder &setInspectFilter(const ValueFilter &filter) {
			entry->inspectFilter = filter;
			return *this;
		}
	};

	typedef StringKeyTable<Entry>::ConstIterator ConstIterator;
	typedef boost::function<void (const Store &store, vector<Error> &errors)> Validator;
	typedef boost::function<json::object (const json::object &effectiveValues)> Normalizer;

private:
	StringKeyTable<Entry> entries;
	boost::container::vector<Validator> validators;
	boost::container::vector<Normalizer> normalizers;
	bool finalized;

	static json::value returnJsonValue(const Store &store, json::value v) {
		return v;
	}

	static json::value getValueFromSubSchema(
		const Store &storeWithMainSchema,
		const Schema *subschema, const Translator *translator,
		const HashedStaticString &key);

	static void validateSubSchema(const Store &store, vector<Error> &errors,
		const Schema *subschema, const Translator *translator,
		const Validator &origValidator);

	static json::object normalizeSubSchema(const json::object &effectiveValues,
		const Schema *mainSchema, const Schema *subschema,
		const Translator *translator, const Normalizer &origNormalizer);

	static json::value getStaticDefaultValue(const Schema::Entry &entry);

	static bool validateNestedSchemaArrayValue(const HashedStaticString &key,
		const Entry &entry, const json::array &value, vector<Error> &errors);
	static bool validateNestedSchemaObjectValue(const HashedStaticString &key,
		const Entry &entry, const json::object &value, vector<Error> &errors);

public:
	Schema()
		: finalized(false)
		{ }

	virtual ~Schema() { }

	/**
	 * Register a new schema entry, possibly with a static default value.
	 */
	EntryBuilder add(const HashedStaticString &key, Type type, unsigned int flags,
		const json::value &defaultValue = json::value(nullptr))
	{
		assert(!finalized);
		if (defaultValue.is_null()) {
			Entry entry(type, (Flags) flags, ValueGetter(), ValueFilter());
			return EntryBuilder(entries.insert(key, entry)->value);
		} else {
			if (flags & REQUIRED) {
				throw ArgumentException(
					"A key cannot be required and have a default value at the same time");
			}
			Entry entry(type, (Flags) flags,
				boost::bind(returnJsonValue, boost::placeholders::_1, defaultValue),
				ValueFilter());
			return EntryBuilder(entries.insert(key, entry)->value);
		}
	}

	/**
	 * Register a new schema entry whose value corresponds to a nested schema.
	 */
	EntryBuilder add(const HashedStaticString &key, Type type,
		const Schema &nestedSchema, unsigned int flags)
	{
		assert(!finalized);
		assert(nestedSchema.finalized);
		assert(type == ARRAY_TYPE || type == OBJECT_TYPE);
		Entry entry(type, (Flags) flags, ValueGetter(), ValueFilter(),
			&nestedSchema);
		return EntryBuilder(entries.insert(key, entry)->value);
	}

	/**
	 * Register a new schema entry with a dynamic default value.
	 */
	EntryBuilder addWithDynamicDefault(const HashedStaticString &key, Type type, unsigned int flags,
		const ValueGetter &defaultValueGetter)
	{
		if (flags & REQUIRED) {
			throw ArgumentException(
				"A key cannot be required and have a default value at the same time");
		}
		assert(!finalized);
		Entry entry(type, (Flags) (flags | _DYNAMIC_DEFAULT_VALUE), defaultValueGetter,
			ValueFilter());
		return EntryBuilder(entries.insert(key, entry)->value);
	}

	void addSubSchema(const Schema &subschema, const Translator &translator) {
		assert(!finalized);
		assert(subschema.finalized);
		Schema::ConstIterator it = subschema.getIterator();

		while (*it != NULL) {
			const HashedStaticString &key = it.getKey();
			const Schema::Entry &entry = it.getValue();
			ValueGetter valueGetter;

			if (entry.defaultValueGetter) {
				if (entry.flags & _DYNAMIC_DEFAULT_VALUE) {
					valueGetter = boost::bind<json::value>(
						getValueFromSubSchema,
						boost::placeholders::_1, &subschema, &translator,
						key);
				} else {
					valueGetter = entry.defaultValueGetter;
				}
			}

			Entry entry2(entry.type, (Flags) (entry.flags | _FROM_SUBSCHEMA),
				valueGetter, entry.inspectFilter);
			entries.insert(translator.reverseTranslateOne(key), entry2);
			it.next();
		}

		boost::container::vector<Validator>::const_iterator v_it, v_end
			= subschema.getValidators().end();
		for (v_it = subschema.getValidators().begin(); v_it != v_end; v_it++) {
			validators.push_back(boost::bind(validateSubSchema,
				boost::placeholders::_1, boost::placeholders::_2,
				&subschema, &translator, *v_it));
		}

		boost::container::vector<Normalizer>::const_iterator n_it, n_end
			= subschema.getNormalizers().end();
		for (n_it = subschema.getNormalizers().begin(); n_it != n_end; n_it++) {
			normalizers.push_back(boost::bind(normalizeSubSchema,
				boost::placeholders::_1, this, &subschema, &translator, *n_it));
		}
	}

	bool erase(const HashedStaticString &key) {
		return entries.erase(key);
	}

	void override(const HashedStaticString &key, Type type, unsigned int flags,
		const json::value &defaultValue = json::value(nullptr))
	{
		erase(key);
		add(key, type, flags, defaultValue);
	}

	void overrideWithDynamicDefault(const HashedStaticString &key, Type type, unsigned int flags,
		const ValueGetter &defaultValueGetter)
	{
		erase(key);
		addWithDynamicDefault(key, type, flags, defaultValueGetter);
	}

	void addValidator(const Validator &validator) {
		assert(!finalized);
		validators.push_back(validator);
	}

	void addNormalizer(const Normalizer &normalizer) {
		assert(!finalized);
		normalizers.push_back(normalizer);
	}

	void finalize() {
		assert(!finalized);
		entries.compact();
		finalized = true;
		validators.shrink_to_fit();
		normalizers.shrink_to_fit();
	}

	bool get(const HashedStaticString &key, const Entry **entry) const {
		assert(finalized);
		return entries.lookup(key, entry);
	}

	/**
	 * Apply standard validation rules -- that do not depend on a particular
	 * configuration store -- to the given configuration key and value.
	 * Validators added with `addValidator()` won't be applied.
	 *
	 * Returns whether validation passed. If not, then an Error is appended
	 * to `errors`.
	 */
	bool validateValue(const HashedStaticString &key, const json::value &value,
		vector<Error> &errors) const
	{
		const Entry *entry;

		assert(finalized);
		if (!entries.lookup(key, &entry)) {
			throw ArgumentException("Unknown key " + key);
		}

		if (value.is_null()) {
			if (entry->flags & REQUIRED) {
				errors.push_back(Error("'{{" + key + "}}' is required"));
				return false;
			} else {
				return true;
			}
		}

		switch (entry->type) {
		case STRING_TYPE:
			if (value.is_string()) {
				return true;
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be a string"));
				return false;
			}
		case INT_TYPE:
			if (value.is_int64()) {
				return true;
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be an integer"));
				return false;
			}
		case UINT_TYPE:
			if (value.is_number() && !value.is_double()) {
				if (value.is_uint64()) {
					return true;
				} else {
					errors.push_back(Error("'{{" + key + "}}' must be greater than 0"));
					return false;
				}
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be an integer"));
				return false;
			}
		case FLOAT_TYPE:
			if (value.is_double()) {
				return true;
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be a number"));
				return false;
			}
		case BOOL_TYPE:
			if (value.is_bool()) {
				return true;
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be a boolean"));
				return false;
			}
		case ARRAY_TYPE:
			if (value.is_array()) {
				if (entry->nestedSchema == NULL) {
					return true;
				} else {
					return validateNestedSchemaArrayValue(key, *entry,
					    value.get_array(), errors);
				}
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be an array"));
				return false;
			}
		case STRING_ARRAY_TYPE:
			if (value.is_array()) {
				json::array::const_iterator it, end = value.get_array().end();
				for (it = value.get_array().begin(); it != end; it++) {
					if (!it->is_string()) {
						errors.push_back(Error("'{{" + key + "}}' may only contain strings"));
						return false;
					}
				}
				return true;
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be an array"));
				return false;
			}
		case OBJECT_TYPE:
			if (value.is_object()) {
				if (entry->nestedSchema == NULL) {
					return true;
				} else {
					return validateNestedSchemaObjectValue(key, *entry,
						value.get_object(), errors);
				}
			} else {
				errors.push_back(Error("'{{" + key + "}}' must be a JSON object"));
				return false;
			}
		case ANY_TYPE:
			return true;
		default:
			P_BUG("Unknown type " + Passenger::toString((int) entry->type));
			return false;
		};
	}

	const boost::container::vector<Validator> &getValidators() const {
		assert(finalized);
		return validators;
	}

	const boost::container::vector<Normalizer> &getNormalizers() const {
		assert(finalized);
		return normalizers;
	}

	ConstIterator getIterator() const {
		assert(finalized);
		return ConstIterator(entries);
	}

	json::object inspect() const {
		assert(finalized);
		json::object result;
		StringKeyTable<Entry>::ConstIterator it(entries);

		while (*it != NULL) {
			result.insert_or_assign(it.getKey(), it.getValue().inspect());
			it.next();
		}

		return result;
	}
};


} // namespace ConfigKit
} // namespace Passenger

#endif /* _PASSENGER_CONFIG_KIT_SCHEMA_H_ */
