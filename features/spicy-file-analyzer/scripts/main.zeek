module @ANALYZER@;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## Record type containing the column fields of the @ANALYZER@ log.
	type Info: record {
		## Current timestamp
		ts: time &log;
		## File ID
		id: string &log;

		# TODO: Adapt subsequent fields as needed.

		## File's content
		content: string &optional &log;
	};

	## Default hook into @ANALYZER@ logging.
	global log_@ANALYZER_LOWER@: event(info: Info);
}

redef record fa_file += {
	@ANALYZER_LOWER@: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(@ANALYZER@::LOG, [$columns=Info, $ev=log_@ANALYZER_LOWER@, $path="@ANALYZER_LOWER@"]);
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( f?$@ANALYZER_LOWER@ )
		return;

	f$@ANALYZER_LOWER@ = Info($ts=network_time(), $id=f$id);
	}

# Example event defined in @ANALYZER_LOWER@.evt.
event @ANALYZER@::content(f: fa_file, content: string)
	{
	hook set_file(f);

	local info = f$@ANALYZER_LOWER@;
	info$content = content;
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f?$@ANALYZER_LOWER@ )
		Log::write(@ANALYZER@::LOG, f$@ANALYZER_LOWER@);
	}
