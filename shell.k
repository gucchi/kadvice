
int main(String[] args)
{
    
    OutputStream os;
    InputStream is;
    String str;

    while(1) {
	OUT << "kadvice>>>";
	str = IN.readLine();
	if (str == "post") {
	    String uri, funcname, group, pri;
	    OUT << "where?>>>";
	    uri = IN.readLine();
	    /* check URI */

	    OUT << "group?[0-7]>>>";
	    group = IN.readLine();
	    /* TODO: check available group */

	    OUT << "priority?[0-7]>>>";
	    pri = IN.readLine();
	    /* TODO: check available priority */	    

	    OUT << "what?>>>";
	    funcname = IN.readLine();
	    /* TODO: check funcname */

	    os = new OutputStream("/proc/kadvice", "w");
	    OUT << "QUERY: "<<  %("post http://localhost/%s{0}.%s{1}.%s{2} %s{3}", uri, group, pri, funcname) << EOL;
	    os << %("post http://localhost/%s{0}.%s{1}.%s{2} %s{3}", uri, group, pri, funcname);
	    in = new InputStream("/proc/kadvice", "r");
	    OUT << in.readLine() << EOL;
	    os.close();
	    in.close();
	} else if (str == 'quit') {
	    break;
	} else {
	    OUT << "unknown method: " << str << EOL;
	}
    }
    OUT << "bye..." << EOL;
    return 0;
}
