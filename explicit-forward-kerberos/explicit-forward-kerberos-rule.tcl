## Rule: Connection-based APM forward-proxy Kerberos authentication
## Author: Kevin Stewart
## Version: 8, 12/2020
## Function: Creates a mechanism to deploy APM Kerberos with connection-based auth behavior. APM NTLM is the only
##           WIA method that currently supports connection-based auth (ability to persist on the authenticated user).
##           Kerberos and Basic persist on the source IP, which is probelematic in NAT environments. This solution
##           uses a sideband access policy evaluation to validate Kerberos credentials against a directory service, and
##           requires the client to pass a valid authorization header in every request. The solution is optimized to query
##           the directory service once for an authenticated user (and within expiry time).
## Instructions: 
## - Create a normal SWG-Explicit auth policy with Kerberos, ensure that Kerberos auth works as expected (attached to LTM VIP)
##      Start -> 407 -> Kerberos Auth -> Allow
## - Remove the 407 agent from the SWG-Explicit auth policy VPE
## - Attach this iRule to the explicit proxy listener virtual server (-xp VIP in SSLO)
## - Modify the AUTH_PROFILE variable to reflect the name of the SWG-Explicit auth policy
## - Modify the AUTH_SESSION_TIMER variable to reflect needed to store "authenticated" user (shorter times more secure, but validate more often)
## - Modify the DEBUG_AUTH variable to enable/disable debug logging to /var/log/ltm
## - Modify the FAILED_AUTH_ATTEMPTS variable to enable and set a failed logon attempt counter
## - Modify the FAILED_AUTH_TIMER variable to adjust the time (in seconds) to track failed logon attempts for a connection

when RULE_INIT {
    ## User-defined: name of the APM authentication profile
    set static::AUTH_PROFILE "/Common/KRB_SWG_MOCK"

    ## User-defined: Amount of time to maintain the authenticated user session (in seconds) - 300 seconds = 5 min
    ## Adjust this setting as needed. Higher setting for longer session, but larger session table
    set static::AUTH_SESSION_TIMER 30

    ## User-defined: DEBUG logging
    set static::DEBUG_AUTH 0
    
    ## User-defined: Authentication attempts (0 = disabled)
    ## Note that a new browser will likely make several update requests before a URL is entered, which will count
    ## against the total failed auth attempts
    set static::FAILED_AUTH_ATTEMPTS 4
    
    ## User-defined: Failed attempts timer (how long to track a failed authentication, in second)
    ## Keep this value reasonably low to allow user to close and re-open browser to try again
    set static::FAILED_AUTH_TIMER 5
}

## NO NEED TO MODIFY BEYOND THIS POINT ##

proc SEND_AUTH_REQUEST { } {
    ## Set up HTTP Basic 407 response
    HTTP::respond 407 Proxy-Authenticate "Negotiate" "Connection" "close" "Cache-Control" "no-cache, must-revalidate" "Pragma" "no-cache" "X-Frame-Options" "DENY" "Content-Type" "text/html; charset=utf-8"

    ## stop further rule processing
    event disable all ; return
}
when HTTP_PROXY_REQUEST {
    ## Generate a random unique ID for logging
    if { $static::DEBUG_AUTH } { set requestid [expr {int(rand() * (99999 + 1 - 10000)) + 10000}] ; log local0. "(${requestid}) [IP::client_addr]:[TCP::client_port] STARTING REQUEST to [HTTP::uri] =========" }
    
    if { not ( [HTTP::header exists "Proxy-Authorization"] ) or not ( [HTTP::header "Proxy-Authorization"] starts_with "Negotiate" )  } {
        ## No Proxy-Authorization received, irrespective of auth_flag - send 407 and reset auth_flag
        if { $static::DEBUG_AUTH } { log local0. "(${requestid}) No Proxy-Authorization header - sending 40x challenge" }
        call SEND_AUTH_REQUEST
    } else {
        ## Generate the lookup key (concat string to 1600 characters to account for changing nonces)
        set pa [findstr [HTTP::header "Proxy-Authorization"] "Negotiate " 10]
        set key "[IP::client_addr]:[string range ${pa} 0 400]"
        if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Key: ${key}" }
        
        if { ( ${static::FAILED_AUTH_ATTEMPTS} ) and ( [table lookup FAIL${key}] ne "" ) and ( [expr { [table lookup FAIL${key}] >= ${static::FAILED_AUTH_ATTEMPTS} }] ) } {
            if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Reached max number of authentication attempts - sending 403" }
            HTTP::respond 403 ; TCP::close ; event disable all ; return
        }

        ## Perform lookup in auth table based on client key: "[IP]:[Proxy-Authorization header]"
        if { [table lookup ${key}] eq "" } {
            if { $static::DEBUG_AUTH } { log local0. "(${requestid}) User key does not exist in session table: initiate sideband auth" }
            ## auth table not 1 (empty) (new or previous failed request) - perform auth validation inside catch incase base64 is bad
            if { [catch {
                ## create flow_sid access session (with short timeout/lifespan)
                set flow_sid [ACCESS::session create -timeout 10 -lifetime 10]            

                ## Call sideband access policy with supplied credentials
                ACCESS::policy evaluate -sid ${flow_sid} -profile $static::AUTH_PROFILE session.logon.last.authparam "${pa}"
                switch [ACCESS::policy result -sid ${flow_sid}] {
                    "allow" {
                        if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Sideband auth return: Allow" }
                        ## set auth table to 1 to prevent subsequent auth validations on successfully auth'ed requests per TCP connection
                        if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Sideband auth user: [ACCESS::session data get -sid ${flow_sid} session.logon.last.username]" }
                        table set ${key} [ACCESS::session data get -sid ${flow_sid} session.logon.last.username] $static::AUTH_SESSION_TIMER
                    }
                    "deny" {
                        ## Authentication failed - send 407 and reset auth_flag
                        if { ${static::FAILED_AUTH_ATTEMPTS} } {
                            if { [table lookup FAIL${key}] eq "" } {
                                table set FAIL${key} 1 ${static::FAILED_AUTH_TIMER}
                                if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Sideband auth return: Deny (1)" }
                                call SEND_AUTH_REQUEST
                            } elseif { [expr { [table lookup FAIL${key}] >= ${static::FAILED_AUTH_ATTEMPTS} }] } {
                                if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Reached max number of authentication attempts - sending 403" }
                                HTTP::respond 403 ; TCP::close ; event disable all ; return
                            } else {
                                table incr FAIL${key}
                                if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Sideband auth return: Deny ([table lookup FAIL${key}])" }
                                call SEND_AUTH_REQUEST
                            }
                        } else {
                            if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Sideband auth return: Deny" }
                            call SEND_AUTH_REQUEST
                        }
                    }
                    default {
                        if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Sideband auth return: Default (invalid auth response)" }
                        call SEND_AUTH_REQUEST
                    }
                }
            } err] } {
                ## Proxy-Authorization decode failed - send 407
                if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Error condition: $err" }
                call SEND_AUTH_REQUEST
            }
        } else {
            if { $static::DEBUG_AUTH } { log local0. "(${requestid}) Allowing request for existing authenticated user: [table lookup ${key}]" }
        }
    }
    if { $static::DEBUG_AUTH } { log local0. "(${requestid}) END REQUEST ==========================" }
    
    sharedvar THISUSER
    if { ( [info exists key] ) and ( [table lookup ${key}] ne "" ) } {
        set THISUSER [table lookup ${key}]
    }
}
