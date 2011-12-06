<?php

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

function fetch_senders_and_recipients($connection, $mailbox, $count)
{
    $selectresult = handmadeimap_select($connection, $mailbox);
    if (!handmadeimap_was_ok())
        die("SELECT failed: ".handmadeimap_get_error()."\n");

    $totalcount = $selectresult['totalcount'];

    $startindex = ($totalcount-$count);
    $endindex = $totalcount;
    
    $fetchresult = handmadeimap_fetch_envelopes($connection, $startindex, $endindex);
    if (!handmadeimap_was_ok())
        die("FETCH failed: ".handmadeimap_get_error()."\n");
    
    $addresslist = array(
        'from' => array(),
        'to' => array(),
        'cc' => array(),
        'bcc' => array(),
    );
    $addresstodisplay = array();
    foreach ($fetchresult as $envelope)
    {
        $from = $envelope['from'];
        $fromcomponents = $from[0];
        $fromaddress = $fromcomponents['address'];
        $fromdisplay = $fromcomponents['display'];
        
        $addresstodisplay[$fromaddress] = $fromdisplay;
        $addresslist['from'][] = $fromaddress;
        
        foreach ($envelope['to'] as $tocomponents)
        {
            $toaddress = $tocomponents['address'];
            $todisplay = $tocomponents['display'];            

            $addresstodisplay[$toaddress] = $todisplay;
            $addresslist['to'][] = $toaddress;
        }

        foreach ($envelope['cc'] as $cccomponents)
        {
            $ccaddress = $cccomponents['address'];
            $ccdisplay = $cccomponents['display'];            

            $addresstodisplay[$ccaddress] = $ccdisplay;
            $addresslist['cc'][] = $ccaddress;
        }

        foreach ($envelope['bcc'] as $bcccomponents)
        {
            $bccaddress = $bcccomponents['address'];
            $bccdisplay = $bcccomponents['display'];            

            $addresstodisplay[$bccaddress] = $bccdisplay;
            $addresslist['bcc'][] = $bccaddress;
        }
    }
    
    $addresscounts = array(
        'from' => array_count_values($addresslist['from']),
        'to' => array_count_values($addresslist['to']),
        'cc' => array_count_values($addresslist['cc']),
        'bcc' => array_count_values($addresslist['bcc']),
    );
    
    $result = array();
    foreach ($addresscounts as $role => $countmap)
    {
        $result[$role] = array();
        foreach ($countmap as $address => $count)
        {
            $result[$role][$address] = array(
                'count' => $count,
                'display' => $addresstodisplay[$address],
            );
        }
    }
        
    return $result;
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
        
    $result = $_SESSION['gmailoauthstate'];

    return $result;
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