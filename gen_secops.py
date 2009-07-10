import os, sys
import re

infile = "security_body.c"
outfile = "secops.out"

inf = open(infile, 'r')
L = inf.readlines();
inf.close()

funcstart = False
counter = 0
rettyupe = ''
funcname = ''
args = []
argvalues = []
argtypes = []

for s in xrange(len(L)):
    p = re.compile('static inline (\w+)\s+security_(\w+)\(([a-zA-Z0-9 ,*_]+)')
    v = p.match(L[s])
    if v != None:
        args = []
        argvalues = []
        argtypes = []
        rettype = v.group(1)
        funcname = v.group(2)
        line = v.group(3)     
        if not '{' in L[s+1]:
            z = s;
            while True:
                z = z + 1
                line = line + L[z]
                if '{' in L[z+1] : break
        line = line.strip();
        line = line.replace("\n", "")
        line = line.replace("\t", "")
                #now we have one liner function signeture
        line = line.replace(")", "")
        args = line.split(",")
        for x in xrange(len(args)):
            args[x] = args[x].strip()
            eargs = args[x].split(" ")
                        # value flag is true, its value. otherwise its type
            valueflag = False
            structflag = False
            constflag = False
            unsignedflag = False
            userflag = False
            for y in xrange(len(eargs)):
                    #print eargs[y]
                if eargs[y] =='struct':
                    structflag = True
                elif eargs[y] == 'const':
                    constflag = True
                            # TODO!: unsinged is difficult.
                            # some like 'unsigned char' or 'unsigned long'
                            # but there's only used 'unsigned' as 'unsigned int'
                            # SOTHAT, we modify kernel source if we find single 'unsigned'
                            # to 'unsigned int'
                elif eargs[y] == 'unsigned':
                    unsignedflag = True
                elif eargs[y] == '__user':
                    userflag = True
                else:
                    if valueflag == True:
                        # its value. check * first
                        if "**" in eargs[y]:
                            t = argtypes.pop()
                            t = t + " **"
                            argtypes.append(t)
                            argvalues.append(eargs[y].replace("**",""))
                        elif '*' in eargs[y]:
                            t = argtypes.pop()
                            t = t + " *"
                            argtypes.append(t)
                            argvalues.append(eargs[y].replace("*",""))
                        else:
                            argvalues.append(eargs[y])
                        valueflag = False
                    else:
                        app = ''
                        if constflag == True:
                            app = app + 'const '
                        if structflag == True:
                            app = app + 'struct '
                        if unsignedflag == True:
                            app = app + 'unsigned '
                        if userflag == True:
                            app = app + '__user '
                        argtypes.append(app + eargs[y])
                        valueflag = True
        outline = L[s].replace("security_", "sc_")
        print outline
    else:
        if 'return 0' in L[s]:
            line = "\treturn sc_check_%s(" % funcname
            if len(argtypes) != len(argvalues):
                print "ERROR!!!", argtypes, argvalues
            for n in xrange(len(argvalues)):
                line = line + "%s," % argvalues[n]
            line = line + ')'
            line = line.replace(',)', ');')
            print line
        elif 'return' in L[s]:
            print "\t/*", L[s].strip(), "*/"
            line = "\treturn sc_check_%s(" % funcname
            if len(argtypes) != len(argvalues):
                print "ERROR!!!", argtypes, argvalues
            for n in xrange(len(argvalues)):
                line = line + "%s," % argvalues[n]
            line = line + ")"
            line = line.replace(',)', ');')
            print line            
        else:
            if '{ }' in L[s] and rettype == 'void':
                line = "{\treturn sc_check_%s(" % funcname
                if len(argtypes) != len(argvalues):
                    print "ERROR!!!", argtypes, argvalues
                for n in xrange(len(argvalues)):
                    line = line + "%s," % argvalues[n]
                line = line + ')'
                line = line.replace(',)', ');}')                
                print line                
            elif '{' in L[s] and rettype == 'void':
                line = L[s] + "\treturn sc_check_%s(" % funcname
                if len(argtypes) != len(argvalues):
                    print "ERROR!!!", argtypes, argvalues
                for n in xrange(len(argvalues)):
                    line = line + "%s," % argvalues[n]
                line = line + ')'
                line = line.replace(',)', ');')                
                print line
            else:
                print L[s]
                
                
