" test for match at first character
au BufNewFile,BufRead *   if match(getline(1), 'node ')==0 | set ft=pcmk | endif
