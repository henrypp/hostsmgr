v2.1 (6 May 2021)
- set win7sp1 as minimum required version
- added multi-core cpu support
- added "-thread" option argument
- use hashtable to avoid source duplicates
- enable eh continuation metadata for builds
- fixed string token used uninitialized memory
- fixed header length can be not enough
- renamed config files
- updated sources list
- updated project sdk
- fixed bugs

v2.0 (26 March 2021)
- increased parsing speed
- added "-noresolve" option to create only host address list
- added "-nobackup" option argument
- added "-nocache" option argument
- added sources from local disk support (issue #9)
- added whitelisting by wildcards (issue #8)
- fixed incorrect utf8 strings conversion
- fixed replacing existing file
- fixed host names parsing
- updated project sdk
- fixed bugs

v1.2 (7 November 2018)
- added backup original hosts file before replacing (use /nobackup to skip)
- added print help for start without arguments
- added program icon
- increased speed

v1.1 (13 September 2016)
- added progress indication
- check for content type of downloaded file
- fixed displaying sources count

v1.0 (21 July 2016)
- first public version
