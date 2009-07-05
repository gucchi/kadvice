infile = "security.c"
inf = open(infile, 'r')
L = inf.readlines()
inf.close()

for s in xrange(len(L)):
    if ("security_ops->" in L[s]):
        print L[s].replace(r"security_ops->", "sc_check_").strip()
    else:
        if ("security_" in L[s]):
            print L[s].replace("security_", "lsm_").strip()
        else:
            print L[s].strip()
