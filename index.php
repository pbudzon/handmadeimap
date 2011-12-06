<?php
require_once ('./config.php');
require_once ('./oauth/gmailoauth.php');
require_once ('./handmadeimap.php');
require_once ('./maildomainutils.php');
require_once ('./gmailutils.php');


// Deals with the workflow of oAuth user authorization. At the start, there's no oAuth information and
// so it will display a link to the Gmail site. If the user visits that link they can authorize us,
// and then they should be redirected back to this page. There should be some access tokens passed back
// when they're redirected, we extract and store them, and then try to call the Gmail IMAP API using them.
function handle_gmail_oauth()
{
    if (!isset($_SESSION['emailaddress']))
    {
        if (!empty($_REQUEST['emailaddress']))
        {
            $_SESSION['emailaddress'] = $_REQUEST['emailaddress'];
        }
        else
        {
?>
            <center>
            <form method="GET" action="index.php">
            Gmail address: <input type="text" size="40" name="emailaddress" value="<?=$email?>"/>
            <input type="submit" value="Authorize"/>
            </form>
            </center>
<?php
            return;
        }

    }

    $emailaddress = $_SESSION['emailaddress'];

	$oauthstate = get_gmail_oauth_state();
    
    // If there's no oAuth state stored at all, then we need to initialize one with our request
    // information, ready to create a request URL.
	if (!isset($oauthstate))
	{
		pete_log('oauth', "No OAuth state found");

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
	if (isset($_REQUEST['oauth_token'])&&
		($oauthstate['access_token']==''))
	{
        error_log('$_REQUEST: '.print_r($_REQUEST, true));
    
		$urlaccesstoken = $_REQUEST['oauth_token'];
		pete_log('oauth', "Found access tokens in the URL - $urlaccesstoken");

		$requesttoken = $oauthstate['request_token'];
		$requesttokensecret = $oauthstate['request_token_secret'];

		pete_log('oauth', "Creating API with $requesttoken, $requesttokensecret");			
	
		$to = new GmailOAuth(
			GOOGLE_API_KEY_PUBLIC, 
			GOOGLE_API_KEY_PRIVATE,
			$requesttoken,
			$requesttokensecret
		);
		
		$tok = $to->getAccessToken();
		
		$accesstoken = $tok['oauth_token'];
		$accesstokensecret = $tok['oauth_token_secret'];

		pete_log('oauth', "Calculated access tokens $accesstoken, $accesstokensecret");			
		
		$oauthstate['access_token'] = $accesstoken;
		$oauthstate['access_token_secret'] = $accesstokensecret;
		$oauthstate['state'] = 'done';

		set_gmail_oauth_state($oauthstate);		
	}

	$state = $oauthstate['state'];
	
	if ($state=='start')
	{
        // This is either the first time the user has seen this page, or they've refreshed it before
        // they've authorized us to access their information. Either way, display a link they can
        // click that will take them to the authorization page.
        // In a real application, you'd probably have the page automatically redirect, since the
        // user has already entered their email address once for us already
		$tokenpublic = $oauthstate['request_token'];
		$to = new GmailOAuth(GOOGLE_API_KEY_PUBLIC, GOOGLE_API_KEY_PRIVATE);
		$requestlink = $to->getAuthorizeURL($tokenpublic, get_current_url());
?>
        <center><h1>Click this link to authorize accessing messages from <?=htmlspecialchars($emailaddress)?></h1></center>
        <br><br>
        <center><a href="<?=$requestlink?>"><?=$requestlink?></a></center>
<?php
	}
	else
	{
        // We've been given some access tokens, so try and use them to make an API call, and
        // display the results.
        
        $accesstoken = $oauthstate['access_token'];
        $accesstokensecret = $oauthstate['access_token_secret'];

        $connection = gmail_login($emailaddress, $accesstoken, $accesstokensecret);
        
        $receivedmailbox = 'Inbox';
        handmadeimap_select($connection, $receivedmailbox);
        $searchresults = handmadeimap_search_message($connection, "Unsubscribe");
        
        $l = 0;
        foreach($searchresults as $messageindex){
            $message = handmadeimap_fetch_message_body($connection, $messageindex);
            var_dump($message);
            $l++;
            if($l > 10) break;
            
        }
    
        
	}
		
}

// This is important! The example code uses session variables to store the user and token information,
// so without this call nothing will work. In a real application you'll want to use a database
// instead, so that the information is stored more persistently.
session_start();

?>
<html>
<head>
<title>Example page for Gmail OAuth</title>
</head>
<body style="font-family:'lucida grande', arial;">
<div style="padding:20px;">
<?php

handle_gmail_oauth();

?>
<br><br><br>
</div>
</body>
</html>