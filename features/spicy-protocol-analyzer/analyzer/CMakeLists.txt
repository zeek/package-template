spicy_add_analyzer(
    NAME @ANALYZER@
    PACKAGE_NAME @NAME@
    SOURCES @ANALYZER_LOWER@.spicy @ANALYZER_LOWER@.evt zeek_@ANALYZER_LOWER@.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
