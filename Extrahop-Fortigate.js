// Omar Mansour, John Randall
const context = 'fortigate';
const debugflag = true;
const ExtraHopGroupName = "blocked-by-extrahop";
const b_rsp = true;
const enableResponseEvent = true;
const FNET_ODS = 'fortigate';
var s_vdom = 'Edge-FW';
var s_tkn = 'API-Token';


if(event=="HTTP_REQUEST"||event=="HTTP_RESPONSE"){
    var sip=Flow.client.ipaddr;
    var dip=Flow.server.ipaddr;
    if(GeoIP.getCountry(sip).countryName=='Jordan'){

        return;
    }

    
if(ThreatIntel.hasIP(sip) ){
    debug("sip: "+ sip + " dip: "+dip);

     // Create Address URI Base
    const s_crtAddr_base = '/api/v2/cmdb/firewall/address/';
    // URL base for the 'Add IP to Group' call.
    const s_addToGrp_base = '/api/v2/cmdb/firewall/addrgrp/' + ExtraHopGroupName;
    // URL base for the 'Delete IP from Group' call.
    const s_DeleteFromGrp_base = '/api/v2/cmdb/firewall/addrgrp/' + ExtraHopGroupName;


     var o_Addr = {
        'name': '',
        'type': 'ipmask',
        'subnet': ''
    };

    // Add IP to group structure
    var o_AddrToAddToGrp = {
        'name': ''

    }

        if (b_rsp) {
        if (debugflag) {
            { debug("Response flag set to true. Requesting a block on traffic to/from  IP " + sip); }
        }
        // Send the three API calls to the Fortinet device. Address object first to make sure it exists.

        if (debugflag) { debug("Sending the createAddr request"); }
        f_crtAddr(s_crtAddr_base, s_vdom, s_tkn, o_Addr, sip); // Create the address object

        // Now we request our new address object is added to our 'blocked' address group
        if (debugflag) { debug("Sending the addGroup request"); }
        f_addToGrp(s_addToGrp_base, s_vdom, s_tkn, o_AddrToAddToGrp, sip); // Add an IP address to the group

        // And finally, ensure the 'blocked' address group doesn't have the 'none' member.
        if (debugflag) { debug("Sending the deleteFromGroup request"); }
        f_deleteFromGrp(s_DeleteFromGrp_base, s_vdom, s_tkn, o_AddrToAddToGrp); // Delete the 'none' IP address from our group

    }

    function f_crtAddr(s_crtAddr_base, s_vdom, s_tkn, o_Addr, o_ip) {

        let s_crtAddr = s_crtAddr_base + "?vdom=" + s_vdom + "&access_token=" + s_tkn;
        
        let o_addr = o_Addr;
        o_addr['name'] = "extrahop_blockip_" + o_ip.toString();
        o_addr['subnet'] = o_ip.toString() + " 255.255.255.255";

        let o_ods = {
            'path': s_crtAddr,
            'headers': {
                "Content-Type": "application/json"
            },
            'payload': JSON.stringify(o_addr),
            'enableResponseEvent': enableResponseEvent,
            'context': context
        };
        if (debugflag) {
            debug("Create address URL is " + s_crtAddr);
            debug("Create Address Payload is " + JSON.stringify(o_ods, null, 1));
        }
        Remote.HTTP(FNET_ODS).request('POST', o_ods);
    }

    function f_addToGrp(s_addToGrp_base, s_vdom, s_tkn, o_addressGroup, o_ip) {

        let s_addToGrpURL = s_addToGrp_base + "/member?vdom=" + s_vdom + "&access_token=" + s_tkn;
        o_AddrToAddToGrp['name'] = "extrahop_blockip_" + o_ip.toString();

        let o_ods = {
            'path': s_addToGrpURL,
            'headers': {
                "Content-Type": "application/json"
            },
            'payload': JSON.stringify(o_AddrToAddToGrp)
        };
        if (debugflag) {
            debug("Add to Group URL is " + s_addToGrpURL);
            debug("Add to Group Payload is " + JSON.stringify(o_ods, null, 2));
        }
        Remote.HTTP(FNET_ODS).request('POST', o_ods);
    }

}

else{
return;
    }

}

    if (event === 'REMOTE_RESPONSE') {
    if (!Remote.response) {
        return;
    }
    var responseObject = Remote.response;
    if (responseObject.context === 'fortigate') {
        var buffer = responseObject.body;
        var headers = responseObject.headers;
        var payload = buffer.decode('utf-8');
        log ('responseObject = '+responseObject.statusCode+', '+JSON.stringify(headers,null,'\t')+', '+payload);

        Network.metricAddCount('Fortigate ODS Responses',1);
        Network.metricAddDetailCount('Fortigate ODS Responses by Status Code',responseObject.statusCode.toString(),1);

        
     }

    }


    






