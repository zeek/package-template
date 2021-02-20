#include "config.h"
#include "Plugin.h"

namespace plugin { namespace @NS_UNDERSCORE@@NAME@ { Plugin plugin; } }

using namespace plugin::@NS_UNDERSCORE@@NAME@;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "@NS@::@NAME@";
	config.description = "TODO: Insert description";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
