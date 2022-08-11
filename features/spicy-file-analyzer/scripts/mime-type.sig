# TODO: Use this file to optionally declare a signature that identifies your
# file type's MIME type through a "magic" content prefix.
signature file-@ANALYZER_LOWER@ {
   file-magic /^Hello/ # TODO: Adjust; this is just what we happen to see in our example test trace
   file-mime "application/x-@ANALYZER_LOWER@", 10
}
