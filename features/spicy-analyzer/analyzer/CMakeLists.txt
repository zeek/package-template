spicy_add_analyzer(
    NAME @name@
    PACKAGE_NAME @name@
    SOURCES @ns@.spicy @ns@.evt zeek_@ns@.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
