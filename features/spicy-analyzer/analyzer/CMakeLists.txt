spicy_add_analyzer(
    NAME @name@
    PACKAGE_NAME @name@
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
