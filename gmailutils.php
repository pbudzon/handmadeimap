<?php
require_once ('./config.php');
require_once ('./oauth/gmailoauth.php');
require_once ('./handmadeimap.php');
require_once ('./maildomainutils.php');
require_once ('./peteutils.php');
/**
 * This is required as all oauth data is saved in session.
 */
session_start();

function handle_gmail_oauth(){
    
    if (!isset($_SESSION['emailaddress'])){
        
        if (!empty($_REQUEST['emailaddress'])){
            $_SESSION['emailaddress'] = $_REQUEST['emailaddress'];
        }
        else{
            
?>
            <form method="GET" action="index.php">
            Gmail address: <input type="text" size="40" name="emailaddress" value=""/>
            <input type="submit" value="Authorize"/>
            </form>
<?php
            return;
        }
    }

    $emailaddress = $_SESSION['emailaddress'];
    $oauthstate = get_gmail_oauth_state();
    
    // If there's no oAuth state stored at all, then we need to initialize one with our request
    // information, ready to create a request URL.
    if (!isset($oauthstate)){
        $to = new GmailOAuth(GOOGLE_API_KEY_PUBLIC, GOOGLE_API_KEY_PRIVATE);
		
        // This call can be unreliable if the Gmail API servers are under a heavy load, so
        // retry it with an increasing amount of back-off if there's a problem.
        $maxretrycount = 1;
        $retrycount = 0;
        while ($retrycount<$maxretrycount)
        {		
                $tok = $to->getRequestToken();
                if (isset($tok['oauth_token'])&&
                        isset($tok['oauth_token_secret']))
                        break;

                $retrycount += 1;
                sleep($retrycount*5);
        }

        $tokenpublic = $tok['oauth_token'];
        $tokenprivate = $tok['oauth_token_secret'];
        $state = 'start';
		
        // Create a new set of information, initially just containing the keys we need to make
        // the request.
        $oauthstate = array(
                'request_token' => $tokenpublic,
                'request_token_secret' => $tokenprivate,
                'access_token' => '',
                'access_token_secret' => '',
                'state' => $state,
        );

        set_gmail_oauth_state($oauthstate);
    }

    // If there's an 'oauth_token' in the URL parameters passed into us, and we don't already
    // have access tokens stored, this is the user being returned from the authorization page.
    // Retrieve the access tokens and store them, and set the state to 'done'.
    if (isset($_REQUEST['oauth_token'])&& ($oauthstate['access_token']=='')){
            
            error_log('$_REQUEST: '.print_r($_REQUEST, true));
            
            $urlaccesstoken = $_REQUEST['oauth_token'];
            $requesttoken = $oauthstate['request_token'];
            $requesttokensecret = $oauthstate['request_token_secret'];
	
            $to = new GmailOAuth(
                    GOOGLE_API_KEY_PUBLIC, 
                    GOOGLE_API_KEY_PRIVATE,
                    $requesttoken,
                    $requesttokensecret
            );
		
            $tok = $to->getAccessToken();

            $accesstoken = $tok['oauth_token'];
            $accesstokensecret = $tok['oauth_token_secret'];

            $oauthstate['access_token'] = $accesstoken;
            $oauthstate['access_token_secret'] = $accesstokensecret;
            $oauthstate['state'] = 'done';

            set_gmail_oauth_state($oauthstate);		
    }

    $state = $oauthstate['state'];
	
    if ($state=='start'){
        // This is either the first time the user has seen this page, or they've refreshed it before
        // they've authorized us to access their information. Either way, display a link they can
        // click that will take them to the authorization page.
        $tokenpublic = $oauthstate['request_token'];
        $to = new GmailOAuth(GOOGLE_API_KEY_PUBLIC, GOOGLE_API_KEY_PRIVATE);
        $requestlink = $to->getAuthorizeURL($tokenpublic, get_current_url());
?>
        <h1>Click this link to authorize accessing messages from <?=htmlspecialchars($emailaddress)?></h1>
        <br><br>
        <a href="<?=$requestlink?>"><?=$requestlink?></a>
<?php
    }
    else{
        // We've been given some access tokens, so try and use them to make an API call, and
        // display the results.
        
        $accesstoken = $oauthstate['access_token'];
        $accesstokensecret = $oauthstate['access_token_secret'];
        
        $connection = gmail_login($emailaddress, $accesstoken, $accesstokensecret);
        
        //now go ahead and do the magic    
	$receivedmailbox = 'Inbox';
        handmadeimap_select($connection, $receivedmailbox);
        $searchresults = handmadeimap_search_message($connection, "Search phrase");
        echo "Found ".count($searchresults)." messages";
        handmadeimap_close_connection($connection);
        
    }	
}

function gmail_login($emailaddress, $accesstoken, $accesstokensecret)
{
    $to = new GmailOAuth(
        GOOGLE_API_KEY_PUBLIC, 
        GOOGLE_API_KEY_PRIVATE,
        $accesstoken,
        $accesstokensecret
    );
    
    $loginstring = $to->getLoginString($emailaddress);

    $imapinfo = get_imap_info_for_address($emailaddress);
    if ($imapinfo==null)
        die("Can't find info for $emailaddress\n");

    $host = $imapinfo['host'];
    $mailserver = 'ssl://'.$host;
    $port = $imapinfo['port'];
    $protocol = $imapinfo['protocol'];
    $mailbox = '[Gmail]/All Mail';

    $connection = handmadeimap_open_connection($mailserver, $port);
    if ($connection==null)
        die("Connection failed: ".handmadeimap_get_error()."\n");

    handmadeimap_capability($connection);
    if (!handmadeimap_was_ok())
        die("CAPABILITY failed: ".handmadeimap_get_error()."\n");

    handmadeimap_login_xoauth($connection, $loginstring);
    if (!handmadeimap_was_ok())
        die("LOGIN failed: ".handmadeimap_get_error()."\n");

    return $connection;
}



// Returns information about the oAuth state for the current user. This includes whether the process
// has been started, if we're waiting for the user to complete the authorization page on the remote
// server, or if the user has authorized us and if so the access keys we need for the API.
// If no oAuth process has been started yet, null is returned and it's up to the client to kick it off
// and set the new information.
// This is all currently stored in session variables, but for real applications you'll probably want
// to move it into your database instead.
//
// The oAuth state is made up of the following members:
//
// request_token: The public part of the token we generated for the authorization request.
// request_token_secret: The secret part of the authorization token we generated.
// access_token: The public part of the token granting us access. Initially ''. 
// access_token_secret: The secret part of the access token. Initially ''.
// state: Where we are in the authorization process. Initially 'start', 'done' once we have access.

function get_gmail_oauth_state()
{
    if (empty($_SESSION['gmailoauthstate']))
        return null;
        
    return $_SESSION['gmailoauthstate'];
}

// Updates the information about the user's progress through the oAuth process.
function set_gmail_oauth_state($state)
{
    $_SESSION['gmailoauthstate'] = $state;
}

// Returns an authenticated object you can use to access the OAuth Gmail API
function get_gmail_oauth_accessor()
{
    $oauthstate = get_gmail_oauth_state();
    if ($oauthstate===null)
        return null;
    
    $accesstoken = $oauthstate['access_token'];
    $accesstokensecret = $oauthstate['access_token_secret'];

    $to = new GmailOAuth(
        GOOGLE_API_KEY_PUBLIC, 
        GOOGLE_API_KEY_PRIVATE,
        $accesstoken,
        $accesstokensecret
    );

    return $to;
}


?>