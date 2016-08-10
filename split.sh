gawk -e '/Calling unwinding from userspace/{ x = "run"++i".txt"; p=1 } /End of unwinding from userspace/{ p=0 } { if (p) print > x }' $1
