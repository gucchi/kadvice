import re

infile = 'smack.c'
outfile = 'hook_smack.out'

inf = open(infile, 'r');
L = inf.readlines();
inf.close();

hooks = []

for s in xrange(len(L)):
    if 'smack' in L[s]:
        line = L[s].strip()
        p = re.compile('\.(\w+)')
        v = p.match(line)
        if v != None:
            hooks.append(v.group(1))

for i in hooks:
    print 'DEF_SC_QUERY("smack", ' + i + ');'

print ''

for i in hooks:
    print 'scube_post_query_str(&scq_' + i + ');'
        
