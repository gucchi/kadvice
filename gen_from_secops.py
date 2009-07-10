import os, sys
import re

infile = 'security.h'
outfile = 'secops.out'

inf = open(infile, 'r')
L = inf.readlines();
inf.close()

counter = 0
for s in xrange(len(L)):
    rettype = ''
    argtypes = []
    argvalues = []
    funcname = ''
    args = []

    funcform = re.compile('\s+(\w+) \(\*(\w+)\)\s*\(([a-zA-Z0-9 _*,]+)')
    m = funcform.match(L[s])
    if m != None:
        rettype = m.group(1)
        funcname = m.group(2)
        line = m.group(3)

        #now, we search for remaining args if its continues to next line
        if not ';' in L[s]:
            z = s;
            while True:
                z = z + 1
                line = line + L[z]
                if ';' in L[z]: break

        #we are done
        line = line.replace("\n", "")
        line = line.replace("\t", "")
        line = line.replace(");","")
        line = line.strip()
        args = line.split(",");
        #print args

        #ok, now we have complete args
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
#its type
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
        #print argtypes, argvalues
        if rettype == 'int':
            outline = 'FUNC%sINT(lsm_acc, %s' % (len(argvalues), funcname)
            outline2 = 'extern int sc_check_%s(' % funcname
        elif rettype == 'void':
            outline = 'FUNC%sVOID(lsm_acc, %s' % (len(argvalues), funcname)
            outline2 = 'extern void sc_check_%s(' % funcname
        else:
            print "ERROR!!"
            
        outline3 = '.%s = sc_%s,' % (funcname, funcname)
        outline4 = '#define __SC_%s  %s' % (funcname, counter)
        if len(argtypes) != len(argvalues):
            print 'ERROR!! there is a matching failure between types and values'
            
        for n in xrange(len(argtypes)):
            outline = outline + ", %s, %s" % (argtypes[n], argvalues[n])
            outline2 = outline2 + ",%s %s" % (argtypes[n], argvalues[n])
        outline = outline + ");"
        outline2 = outline2.replace("(,", "(")
        outline2 = outline2 + ");"
        print outline3
        
        counter = counter + 1
        

