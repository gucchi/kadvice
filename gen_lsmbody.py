import re

infile = "capability.c"
inf = open(infile, 'r')
L = inf.readlines()
inf.close()

funcname = ''

for s in xrange(len(L)):

    funcform = re.compile('static \w+ cap_([a-zA-Z_]+)')
    m = funcform.match(L[s])
    if m != None:
#        print L[s].strip()
        funcname = m.group(1)
        #print funcname
        if ("cap_" in L[s]):
            print L[s].replace("cap_", "sc_").strip()
        else:
                print L[s].strip()

    else :
        # there is only one function, "return 1"
        if "return 0" in L[s]:
            print L[s].replace("0" , "sc_%s()" % funcname)
        elif "{" in L[s] and "}" in L[s+1]:
            print L[s].replace("}", "return sc_%s()")
        elif
