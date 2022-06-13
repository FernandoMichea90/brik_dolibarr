<?php
/* Copyright (C) 2002-2007  Rodolphe Quiedeville    <rodolphe@quiedeville.org>
 * Copyright (C) 2003       Xavier Dutoit           <doli@sydesy.com>
 * Copyright (C) 2004-2021  Laurent Destailleur     <eldy@users.sourceforge.net>
 * Copyright (C) 2004       Sebastien Di Cintio     <sdicintio@ressource-toi.org>
 * Copyright (C) 2004       Benoit Mortier          <benoit.mortier@opensides.be>
 * Copyright (C) 2005-2021  Regis Houssin           <regis.houssin@inodbox.com>
 * Copyright (C) 2011-2014  Philippe Grand          <philippe.grand@atoo-net.com>
 * Copyright (C) 2008       Matteli
 * Copyright (C) 2011-2016  Juanjo Menent           <jmenent@2byte.es>
 * Copyright (C) 2012       Christophe Battarel     <christophe.battarel@altairis.fr>
 * Copyright (C) 2014-2015  Marcos García           <marcosgdf@gmail.com>
 * Copyright (C) 2015       Raphaël Doursenaud      <rdoursenaud@gpcsolutions.fr>
 * Copyright (C) 2020       Demarest Maxime         <maxime@indelog.fr>
 * Copyright (C) 2020       Charlene Benke          <charlie@patas-monkey.com>
 * Copyright (C) 2021       Frédéric France         <frederic.france@netlogic.fr>
 * Copyright (C) 2021       Alexandre Spangaro      <aspangaro@open-dsi.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 *	\file       htdocs/main.inc.php
 *	\ingroup	core
 *	\brief      File that defines environment for Dolibarr GUI pages only (file not required by scripts)
 */

//@ini_set('memory_limit', '128M');	// This may be useless if memory is hard limited by your PHP

// For optional tuning. Enabled if environment variable MAIN_SHOW_TUNING_INFO is defined.
$micro_start_time = 0;
if (!empty($_SERVER['MAIN_SHOW_TUNING_INFO'])) {
	list($usec, $sec) = explode(" ", microtime());
	$micro_start_time = ((float) $usec + (float) $sec);
	// Add Xdebug code coverage
	//define('XDEBUGCOVERAGE',1);
	if (defined('XDEBUGCOVERAGE')) {
		xdebug_start_code_coverage();
	}
}


/**
 * Return the real char for a numeric entities.
 * WARNING: This function is required by testSqlAndScriptInject() and the GETPOST 'restricthtml'. Regex calling must be similar.
 *
 * @param	string		$matches			String of numeric entity
 * @return	string							New value
 */
function realCharForNumericEntities($matches)
{
	$newstringnumentity = preg_replace('/;$/', '', $matches[1]);
	//print  ' $newstringnumentity='.$newstringnumentity;

	if (preg_match('/^x/i', $newstringnumentity)) {
		$newstringnumentity = hexdec(preg_replace('/^x/i', '', $newstringnumentity));
	}

	// The numeric value we don't want as entities because they encode ascii char, and why using html entities on ascii except for haking ?
	if (($newstringnumentity >= 65 && $newstringnumentity <= 90) || ($newstringnumentity >= 97 && $newstringnumentity <= 122)) {
		return chr((int) $newstringnumentity);
	}

	return '&#'.$matches[1]; // Value will be unchanged because regex was /&#(  )/
}

/**
 * Security: WAF layer for SQL Injection and XSS Injection (scripts) protection (Filters on GET, POST, PHP_SELF).
 * Warning: Such a protection can't be enough. It is not reliable as it will always be possible to bypass this. Good protection can
 * only be guaranted by escaping data during output.
 *
 * @param		string		$val		Brut value found into $_GET, $_POST or PHP_SELF
 * @param		string		$type		0=POST, 1=GET, 2=PHP_SELF, 3=GET without sql reserved keywords (the less tolerant test)
 * @return		int						>0 if there is an injection, 0 if none
 */
function testSqlAndScriptInject($val, $type)
{
	// Decode string first because a lot of things are obfuscated by encoding or multiple encoding.
	// So <svg o&#110;load='console.log(&quot;123&quot;)' become <svg onload='console.log(&quot;123&quot;)'
	// So "&colon;&apos;" become ":'" (due to ENT_HTML5)
	// Loop to decode until no more things to decode.
	//print "before decoding $val\n";
	do {
		$oldval = $val;
		$val = html_entity_decode($val, ENT_QUOTES | ENT_HTML5);
		//$val = preg_replace_callback('/&#(x?[0-9][0-9a-f]+;?)/i', 'realCharForNumericEntities', $val); // Sometimes we have entities without the ; at end so html_entity_decode does not work but entities is still interpreted by browser.
		$val = preg_replace_callback('/&#(x?[0-9][0-9a-f]+;?)/i', function ($m) {
			return realCharForNumericEntities($m); }, $val);
		// We clean html comments because some hacks try to obfuscate evil strings by inserting HTML comments. Example: on<!-- -->error=alert(1)
		$val = preg_replace('/<!--[^>]*-->/', '', $val);
		$val = preg_replace('/[\r\n]/', '', $val);
	} while ($oldval != $val);
	//print "type = ".$type." after decoding: ".$val."\n";

	$inj = 0;

	// We check string because some hacks try to obfuscate evil strings by inserting non printable chars. Example: 'java(ascci09)scr(ascii00)ipt' is processed like 'javascript' (whatever is place of evil ascii char)
	// We should use dol_string_nounprintableascii but function is not yet loaded/available
	// Example of valid UTF8 chars:
	// utf8=utf8mb3:    '\x09', '\x0A', '\x0D', '\x7E'
	// utf8=utf8mb3: 	'\xE0\xA0\x80'
	// utf8mb4: 		'\xF0\x9D\x84\x9E'   (but this may be refused by the database insert if pagecode is utf8=utf8mb3)
	$newval = preg_replace('/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/u', '', $val); // /u operator makes UTF8 valid characters being ignored so are not included into the replace

	// Note that $newval may also be completely empty '' when non valid UTF8 are found.
	if ($newval != $val) {
		// If $val has changed after removing non valid UTF8 chars, it means we have an evil string.
		$inj += 1;
	}
	//print 'type='.$type.'-val='.$val.'-newval='.$newval."-inj=".$inj."\n";

	// For SQL Injection (only GET are used to scan for such injection strings)
	if ($type == 1 || $type == 3) {
		$inj += preg_match('/delete\s+from/i', $val);
		$inj += preg_match('/create\s+table/i', $val);
		$inj += preg_match('/insert\s+into/i', $val);
		$inj += preg_match('/select\s+from/i', $val);
		$inj += preg_match('/into\s+(outfile|dumpfile)/i', $val);
		$inj += preg_match('/user\s*\(/i', $val); // avoid to use function user() or mysql_user() that return current database login
		$inj += preg_match('/information_schema/i', $val); // avoid to use request that read information_schema database
		$inj += preg_match('/<svg/i', $val); // <svg can be allowed in POST
		$inj += preg_match('/update.+set.+=/i', $val);
		$inj += preg_match('/union.+select/i', $val);
	}
	if ($type == 3) {
		$inj += preg_match('/select|update|delete|truncate|replace|group\s+by|concat|count|from|union/i', $val);
	}
	if ($type != 2) {	// Not common key strings, so we can check them both on GET and POST
		$inj += preg_match('/updatexml\(/i', $val);
		$inj += preg_match('/(\.\.%2f)+/i', $val);
		$inj += preg_match('/\s@@/', $val);
	}
	// For XSS Injection done by closing textarea to execute content into a textarea field
	$inj += preg_match('/<\/textarea/i', $val);
	// For XSS Injection done by adding javascript with script
	// This is all cases a browser consider text is javascript:
	// When it found '<script', 'javascript:', '<style', 'onload\s=' on body tag, '="&' on a tag size with old browsers
	// All examples on page: http://ha.ckers.org/xss.html#XSScalc
	// More on https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
	$inj += preg_match('/<audio/i', $val);
	$inj += preg_match('/<embed/i', $val);
	$inj += preg_match('/<iframe/i', $val);
	$inj += preg_match('/<object/i', $val);
	$inj += preg_match('/<script/i', $val);
	$inj += preg_match('/Set\.constructor/i', $val); // ECMA script 6
	if (!defined('NOSTYLECHECK')) {
		$inj += preg_match('/<style/i', $val);
	}
	$inj += preg_match('/base\s+href/si', $val);
	$inj += preg_match('/=data:/si', $val);
	// List of dom events is on https://www.w3schools.com/jsref/dom_obj_event.asp and https://developer.mozilla.org/en-US/docs/Web/API/GlobalEventHandlers
	$inj += preg_match('/on(mouse|drag|key|load|touch|pointer|select|transition)([a-z]*)\s*=/i', $val); // onmousexxx can be set on img or any html tag like <img title='...' onmouseover=alert(1)>
	$inj += preg_match('/on(abort|afterprint|animation|auxclick|beforecopy|beforecut|beforeprint|beforeunload|blur|cancel|canplay|canplaythrough|change|click|close|contextmenu|cuechange|copy|cut)\s*=/i', $val);
	$inj += preg_match('/on(dblclick|drop|durationchange|emptied|ended|error|focus|focusin|focusout|formdata|gotpointercapture|hashchange|input|invalid)\s*=/i', $val);
	$inj += preg_match('/on(lostpointercapture|offline|online|pagehide|pageshow)\s*=/i', $val);
	$inj += preg_match('/on(paste|pause|play|playing|progress|ratechange|reset|resize|scroll|search|seeked|seeking|show|stalled|start|submit|suspend)\s*=/i', $val);
	$inj += preg_match('/on(timeupdate|toggle|unload|volumechange|waiting|wheel)\s*=/i', $val);

	// We refuse html into html because some hacks try to obfuscate evil strings by inserting HTML into HTML. Example: <img on<a>error=alert(1) to bypass test on onerror
	$tmpval = preg_replace('/<[^<]+>/', '', $val);
	// List of dom events is on https://www.w3schools.com/jsref/dom_obj_event.asp and https://developer.mozilla.org/en-US/docs/Web/API/GlobalEventHandlers
	$inj += preg_match('/on(mouse|drag|key|load|touch|pointer|select|transition)([a-z]*)\s*=/i', $val); // onmousexxx can be set on img or any html tag like <img title='...' onmouseover=alert(1)>
	$inj += preg_match('/on(abort|afterprint|animation|auxclick|beforeprint|beforeunload|blur|cancel|canplay|canplaythrough|change|click|close|contextmenu|cuechange|copy|cut)\s*=/i', $tmpval);
	$inj += preg_match('/on(dblclick|drop|durationchange|emptied|ended|error|focus|focusin|focusout|formdata|gotpointercapture|hashchange|input|invalid)\s*=/i', $tmpval);
	$inj += preg_match('/on(lostpointercapture|offline|online|pagehide|pageshow)\s*=/i', $tmpval);
	$inj += preg_match('/on(paste|pause|play|playing|progress|ratechange|reset|resize|scroll|search|seeked|seeking|show|stalled|start|submit|suspend)\s*=/i', $tmpval);
	$inj += preg_match('/on(timeupdate|toggle|unload|volumechange|waiting|wheel)\s*=/i', $tmpval);

	//$inj += preg_match('/on[A-Z][a-z]+\*=/', $val);   // To lock event handlers onAbort(), ...
	$inj += preg_match('/&#58;|&#0000058|&#x3A/i', $val); // refused string ':' encoded (no reason to have it encoded) to lock 'javascript:...'
	$inj += preg_match('/javascript\s*:/i', $val);
	$inj += preg_match('/vbscript\s*:/i', $val);
	// For XSS Injection done by adding javascript closing html tags like with onmousemove, etc... (closing a src or href tag with not cleaned param)
	if ($type == 1) {
		$val = str_replace('enclosure="', 'enclosure=X', $val); // We accept enclosure=" for the export/import module
		$inj += preg_match('/"/i', $val); // We refused " in GET parameters value.
	}
	if ($type == 2) {
		$inj += preg_match('/[:;"\'<>\?\(\){}\$%]/', $val); // PHP_SELF is a file system (or url path without parameters). It can contains spaces.
	}

	return $inj;
}

/**
 * Return true if security check on parameters are OK, false otherwise.
 *
 * @param		string			$var		Variable name
 * @param		string			$type		1=GET, 0=POST, 2=PHP_SELF
 * @return		boolean|null				true if there is no injection. Stop code if injection found.
 */
function analyseVarsForSqlAndScriptsInjection(&$var, $type)
{
	if (is_array($var)) {
		foreach ($var as $key => $value) {	// Warning, $key may also be used for attacks
			if (analyseVarsForSqlAndScriptsInjection($key, $type) && analyseVarsForSqlAndScriptsInjection($value, $type)) {
				//$var[$key] = $value;	// This is useless
			} else {
				// Get remote IP: PS: We do not use getRemoteIP(), function is not yet loaded and we need a value that can't be spoofed
				$ip = (empty($_SERVER['REMOTE_ADDR']) ? 'unknown' : $_SERVER['REMOTE_ADDR']);
				$errormessage = 'Access refused to '.$ip.' by SQL or Script injection protection in main.inc.php - GETPOST type='.htmlentities($type).' paramkey='.htmlentities($key).' paramvalue='.htmlentities($value).' page='.htmlentities($_SERVER["REQUEST_URI"]);
				print $errormessage;
				// Add entry into error log
				if (function_exists('error_log')) {
					error_log($errormessage);
				}
				// TODO Add entry into security audit table
				exit;
			}
		}
		return true;
	} else {
		return (testSqlAndScriptInject($var, $type) <= 0);
	}
}


// Check consistency of NOREQUIREXXX DEFINES
if ((defined('NOREQUIREDB') || defined('NOREQUIRETRAN')) && !defined('NOREQUIREMENU')) {
	print 'If define NOREQUIREDB or NOREQUIRETRAN are set, you must also set NOREQUIREMENU or not set them.';
	exit;
}
if (defined('NOREQUIREUSER') && !defined('NOREQUIREMENU')) {
	print 'If define NOREQUIREUSER is set, you must also set NOREQUIREMENU or not set it.';
	exit;
}

// Sanity check on URL
if (!empty($_SERVER["PHP_SELF"])) {
	$morevaltochecklikepost = array($_SERVER["PHP_SELF"]);
	analyseVarsForSqlAndScriptsInjection($morevaltochecklikepost, 2);
}
// Sanity check on GET parameters
if (!defined('NOSCANGETFORINJECTION') && !empty($_SERVER["QUERY_STRING"])) {
	// Note: QUERY_STRING is url encoded, but $_GET and $_POST are already decoded
	// Because the analyseVarsForSqlAndScriptsInjection is designed for already url decoded value, we must decode QUERY_STRING
	// Another solution is to provide $_GET as parameter
	$morevaltochecklikeget = array(urldecode($_SERVER["QUERY_STRING"]));
	analyseVarsForSqlAndScriptsInjection($morevaltochecklikeget, 1);
}
// Sanity check on POST
if (!defined('NOSCANPOSTFORINJECTION')) {
	analyseVarsForSqlAndScriptsInjection($_POST, 0);
}

// This is to make Dolibarr working with Plesk
if (!empty($_SERVER['DOCUMENT_ROOT']) && substr($_SERVER['DOCUMENT_ROOT'], -6) !== 'htdocs') {
	set_include_path($_SERVER['DOCUMENT_ROOT'].'/htdocs');
}


// Include the conf.php and functions.lib.php and security.lib.php. This defined the constants like DOL_DOCUMENT_ROOT, DOL_DATA_ROOT, DOL_URL_ROOT...
require_once 'filefunc.inc.php';

// If there is a POST parameter to tell to save automatically some POST parameters into cookies, we do it.
// This is used for example by form of boxes to save personalization of some options.
// DOL_AUTOSET_COOKIE=cookiename:val1,val2 and  cookiename_val1=aaa cookiename_val2=bbb will set cookie_name with value json_encode(array('val1'=> , ))
if (!empty($_POST["DOL_AUTOSET_COOKIE"])) {
	$tmpautoset = explode(':', $_POST["DOL_AUTOSET_COOKIE"], 2);
	$tmplist = explode(',', $tmpautoset[1]);
	$cookiearrayvalue = array();
	foreach ($tmplist as $tmpkey) {
		$postkey = $tmpautoset[0].'_'.$tmpkey;
		//var_dump('tmpkey='.$tmpkey.' postkey='.$postkey.' value='.$_POST[$postkey]);
		if (!empty($_POST[$postkey])) {
			$cookiearrayvalue[$tmpkey] = $_POST[$postkey];
		}
	}
	$cookiename = $tmpautoset[0];
	$cookievalue = json_encode($cookiearrayvalue);
	//var_dump('setcookie cookiename='.$cookiename.' cookievalue='.$cookievalue);
	setcookie($cookiename, empty($cookievalue) ? '' : $cookievalue, empty($cookievalue) ? 0 : (time() + (86400 * 354)), '/', null, (empty($dolibarr_main_force_https) ? false : true), true); // keep cookie 1 year and add tag httponly
	if (empty($cookievalue)) {
		unset($_COOKIE[$cookiename]);
	}
}

// Set the handler of session
// if (ini_get('session.save_handler') == 'user')
if (!empty($php_session_save_handler) && $php_session_save_handler == 'db') {
	require_once 'core/lib/phpsessionin'.$php_session_save_handler.'.lib.php';
}

// Init session. Name of session is specific to Dolibarr instance.
// Must be done after the include of filefunc.inc.php so global variables of conf file are defined (like $dolibarr_main_instance_unique_id or $dolibarr_main_force_https).
// Note: the function dol_getprefix is defined into functions.lib.php but may have been defined to return a different key to manage another area to protect.
$prefix = dol_getprefix('');
$sessionname = 'DOLSESSID_'.$prefix;
$sessiontimeout = 'DOLSESSTIMEOUT_'.$prefix;
if (!empty($_COOKIE[$sessiontimeout])) {
	ini_set('session.gc_maxlifetime', $_COOKIE[$sessiontimeout]);
}


// This create lock, released by session_write_close() or end of page.
// We need this lock as long as we read/write $_SESSION ['vars']. We can remove lock when finished.
if (!defined('NOSESSION')) {
	session_set_cookie_params(0, '/', null, (empty($dolibarr_main_force_https) ? false : true), true); // Add tag secure and httponly on session cookie (same as setting session.cookie_httponly into php.ini). Must be called before the session_start.
	session_name($sessionname);
	session_start();	// This call the open and read of session handler
	//exit;	// this exist generates a call to write and close
}


// Init the 5 global objects, this include will make the 'new Xxx()' and set properties for: $conf, $db, $langs, $user, $mysoc
require_once 'master.inc.php';

// If software has been locked. Only login $conf->global->MAIN_ONLY_LOGIN_ALLOWED is allowed.
if (!empty($conf->global->MAIN_ONLY_LOGIN_ALLOWED)) {
	$ok = 0;
	if ((!session_id() || !isset($_SESSION["dol_login"])) && !isset($_POST["username"]) && !empty($_SERVER["GATEWAY_INTERFACE"])) {
		$ok = 1; // We let working pages if not logged and inside a web browser (login form, to allow login by admin)
	} elseif (isset($_POST["username"]) && $_POST["username"] == $conf->global->MAIN_ONLY_LOGIN_ALLOWED) {
		$ok = 1; // We let working pages that is a login submission (login submit, to allow login by admin)
	} elseif (defined('NOREQUIREDB')) {
		$ok = 1; // We let working pages that don't need database access (xxx.css.php)
	} elseif (defined('EVEN_IF_ONLY_LOGIN_ALLOWED')) {
		$ok = 1; // We let working pages that ask to work even if only login enabled (logout.php)
	} elseif (session_id() && isset($_SESSION["dol_login"]) && $_SESSION["dol_login"] == $conf->global->MAIN_ONLY_LOGIN_ALLOWED) {
		$ok = 1; // We let working if user is allowed admin
	}
	if (!$ok) {
		if (session_id() && isset($_SESSION["dol_login"]) && $_SESSION["dol_login"] != $conf->global->MAIN_ONLY_LOGIN_ALLOWED) {
			print 'Sorry, your application is offline.'."\n";
			print 'You are logged with user "'.$_SESSION["dol_login"].'" and only administrator user "'.$conf->global->MAIN_ONLY_LOGIN_ALLOWED.'" is allowed to connect for the moment.'."\n";
			$nexturl = DOL_URL_ROOT.'/user/logout.php?token='.newToken();
			print 'Please try later or <a href="'.$nexturl.'">click here to disconnect and change login user</a>...'."\n";
		} else {
			print 'Sorry, your application is offline. Only administrator user "'.$conf->global->MAIN_ONLY_LOGIN_ALLOWED.'" is allowed to connect for the moment.'."\n";
			$nexturl = DOL_URL_ROOT.'/';
			print 'Please try later or <a href="'.$nexturl.'">click here to change login user</a>...'."\n";
		}
		exit;
	}
}


// Activate end of page function
register_shutdown_function('dol_shutdown');

// Load debugbar
if (!empty($conf->debugbar->enabled) && !GETPOST('dol_use_jmobile') && empty($_SESSION['dol_use_jmobile'])) {
	global $debugbar;
	include_once DOL_DOCUMENT_ROOT.'/debugbar/class/DebugBar.php';
	$debugbar = new DolibarrDebugBar();
	$renderer = $debugbar->getRenderer();
	if (empty($conf->global->MAIN_HTML_HEADER)) {
		$conf->global->MAIN_HTML_HEADER = '';
	}
	$conf->global->MAIN_HTML_HEADER .= $renderer->renderHead();

	$debugbar['time']->startMeasure('pageaftermaster', 'Page generation (after environment init)');
}

// Detection browser
if (isset($_SERVER["HTTP_USER_AGENT"])) {
	$tmp = getBrowserInfo($_SERVER["HTTP_USER_AGENT"]);
	$conf->browser->name = $tmp['browsername'];
	$conf->browser->os = $tmp['browseros'];
	$conf->browser->version = $tmp['browserversion'];
	$conf->browser->layout = $tmp['layout']; // 'classic', 'phone', 'tablet'
	//var_dump($conf->browser);

	if ($conf->browser->layout == 'phone') {
		$conf->dol_no_mouse_hover = 1;
	}
}

// If theme is forced
if (GETPOST('theme', 'aZ09')) {
	$conf->theme = GETPOST('theme', 'aZ09');
	$conf->css = "/theme/".$conf->theme."/style.css.php";
}

// Set global MAIN_OPTIMIZEFORTEXTBROWSER (must be before login part)
if (GETPOST('textbrowser', 'int') || (!empty($conf->browser->name) && $conf->browser->name == 'lynxlinks')) {   // If we must enable text browser
	$conf->global->MAIN_OPTIMIZEFORTEXTBROWSER = 1;
}

// Force HTTPS if required ($conf->file->main_force_https is 0/1 or 'https dolibarr root url')
// $_SERVER["HTTPS"] is 'on' when link is https, otherwise $_SERVER["HTTPS"] is empty or 'off'
if (!empty($conf->file->main_force_https) && (empty($_SERVER["HTTPS"]) || $_SERVER["HTTPS"] != 'on')) {
	$newurl = '';
	if (is_numeric($conf->file->main_force_https)) {
		if ($conf->file->main_force_https == '1' && !empty($_SERVER["SCRIPT_URI"])) {	// If SCRIPT_URI supported by server
			if (preg_match('/^http:/i', $_SERVER["SCRIPT_URI"]) && !preg_match('/^https:/i', $_SERVER["SCRIPT_URI"])) {	// If link is http
				$newurl = preg_replace('/^http:/i', 'https:', $_SERVER["SCRIPT_URI"]);
			}
		} else {
			// Check HTTPS environment variable (Apache/mod_ssl only)
			$newurl = preg_replace('/^http:/i', 'https:', DOL_MAIN_URL_ROOT).$_SERVER["REQUEST_URI"];
		}
	} else {
		// Check HTTPS environment variable (Apache/mod_ssl only)
		$newurl = $conf->file->main_force_https.$_SERVER["REQUEST_URI"];
	}
	// Start redirect
	if ($newurl) {
		header_remove(); // Clean header already set to be sure to remove any header like "Set-Cookie: DOLSESSID_..." from non HTTPS answers
		dol_syslog("main.inc: dolibarr_main_force_https is on, we make a redirect to ".$newurl);
		header("Location: ".$newurl);
		exit;
	} else {
		dol_syslog("main.inc: dolibarr_main_force_https is on but we failed to forge new https url so no redirect is done", LOG_WARNING);
	}
}

if (!defined('NOLOGIN') && !defined('NOIPCHECK') && !empty($dolibarr_main_restrict_ip)) {
	$listofip = explode(',', $dolibarr_main_restrict_ip);
	$found = false;
	foreach ($listofip as $ip) {
		$ip = trim($ip);
		if ($ip == $_SERVER['REMOTE_ADDR']) {
			$found = true;
			break;
		}
	}
	if (!$found) {
		print 'Access refused by IP protection. Your detected IP is '.$_SERVER['REMOTE_ADDR'];
		exit;
	}
}

// Loading of additional presentation includes
if (!defined('NOREQUIREHTML')) {
	require_once DOL_DOCUMENT_ROOT.'/core/class/html.form.class.php'; // Need 660ko memory (800ko in 2.2)
}
if (!defined('NOREQUIREAJAX')) {
	require_once DOL_DOCUMENT_ROOT.'/core/lib/ajax.lib.php'; // Need 22ko memory
}

// If install or upgrade process not done or not completely finished, we call the install page.
if (!empty($conf->global->MAIN_NOT_INSTALLED) || !empty($conf->global->MAIN_NOT_UPGRADED)) {
	dol_syslog("main.inc: A previous install or upgrade was not complete. Redirect to install page.", LOG_WARNING);
	header("Location: ".DOL_URL_ROOT."/install/index.php");
	exit;
}
// If an upgrade process is required, we call the install page.
if ((!empty($conf->global->MAIN_VERSION_LAST_UPGRADE) && ($conf->global->MAIN_VERSION_LAST_UPGRADE != DOL_VERSION))
|| (empty($conf->global->MAIN_VERSION_LAST_UPGRADE) && !empty($conf->global->MAIN_VERSION_LAST_INSTALL) && ($conf->global->MAIN_VERSION_LAST_INSTALL != DOL_VERSION))) {
	$versiontocompare = empty($conf->global->MAIN_VERSION_LAST_UPGRADE) ? $conf->global->MAIN_VERSION_LAST_INSTALL : $conf->global->MAIN_VERSION_LAST_UPGRADE;
	require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
	$dolibarrversionlastupgrade = preg_split('/[.-]/', $versiontocompare);
	$dolibarrversionprogram = preg_split('/[.-]/', DOL_VERSION);
	$rescomp = versioncompare($dolibarrversionprogram, $dolibarrversionlastupgrade);
	if ($rescomp > 0) {   // Programs have a version higher than database. We did not add "&& $rescomp < 3" because we want upgrade process for build upgrades
		dol_syslog("main.inc: database version ".$versiontocompare." is lower than programs version ".DOL_VERSION.". Redirect to install page.", LOG_WARNING);
		header("Location: ".DOL_URL_ROOT."/install/index.php");
		exit;
	}
}

// Creation of a token against CSRF vulnerabilities
if (!defined('NOTOKENRENEWAL') && !defined('NOSESSION')) {
	// No token renewal on .css.php, .js.php and .json.php
	if (!preg_match('/\.(css|js|json)\.php$/', $_SERVER["PHP_SELF"])) {
		// Rolling token at each call ($_SESSION['token'] contains token of previous page)
		if (isset($_SESSION['newtoken'])) {
			$_SESSION['token'] = $_SESSION['newtoken'];
		}

		if (!isset($_SESSION['newtoken']) || getDolGlobalInt('MAIN_SECURITY_CSRF_TOKEN_RENEWAL_ON_EACH_CALL')) {
			// Save in $_SESSION['newtoken'] what will be next token. Into forms, we will add param token = $_SESSION['newtoken']
			$token = dol_hash(uniqid(mt_rand(), false), 'md5'); // Generates a hash of a random number. We don't need a secured hash, just a changing random value.
			$_SESSION['newtoken'] = $token;
			dol_syslog("NEW TOKEN generated by : ".$_SERVER['PHP_SELF'], LOG_DEBUG);
		}
	}
}

//dol_syslog("aaaa - ".defined('NOCSRFCHECK')." - ".$dolibarr_nocsrfcheck." - ".$conf->global->MAIN_SECURITY_CSRF_WITH_TOKEN." - ".$_SERVER['REQUEST_METHOD']." - ".GETPOST('token', 'alpha'));

// Check validity of token, only if option MAIN_SECURITY_CSRF_WITH_TOKEN enabled or if constant CSRFCHECK_WITH_TOKEN is set into page
if ((!defined('NOCSRFCHECK') && empty($dolibarr_nocsrfcheck) && getDolGlobalInt('MAIN_SECURITY_CSRF_WITH_TOKEN')) || defined('CSRFCHECK_WITH_TOKEN')) {
	// Array of action code where CSRFCHECK with token will be forced (so token must be provided on url request)
	$sensitiveget = false;
	if ((GETPOSTISSET('massaction') || GETPOST('action', 'aZ09')) && getDolGlobalInt('MAIN_SECURITY_CSRF_WITH_TOKEN') >= 3) {
		// All GET actions and mass actions are processed as sensitive.
		if (GETPOSTISSET('massaction') || !in_array(GETPOST('action', 'aZ09'), array('create', 'file_manager'))) {	// We exclude the case action='create' and action='file_manager' that are legitimate
			$sensitiveget = true;
		}
	} elseif (getDolGlobalInt('MAIN_SECURITY_CSRF_WITH_TOKEN') >= 2) {
		// Few GET actions coded with a &token into url are processed as sensitive.
		$arrayofactiontoforcetokencheck = array(
			'activate',
			'doprev', 'donext', 'dvprev', 'dvnext',
			'install',
			'reopen'
		);
		if (in_array(GETPOST('action', 'aZ09'), $arrayofactiontoforcetokencheck)) {
			$sensitiveget = true;
		}
		if (preg_match('/^(add|classify|close|confirm|copy|del|disable|enable|remove|set|unset|update|save)/', GETPOST('action', 'aZ09'))) {
			$sensitiveget = true;
		}
	}
	// Check a token is provided for all cases that need a mandatory token
	// (all POST actions + all login, actions and mass actions on pages with CSRFCHECK_WITH_TOKEN set + all sensitive GET actions)
	if (
		$_SERVER['REQUEST_METHOD'] == 'POST' ||
		$sensitiveget ||
		GETPOSTISSET('massaction') ||
		((GETPOSTISSET('actionlogin') || GETPOSTISSET('action')) && defined('CSRFCHECK_WITH_TOKEN'))
	) {
		// If token is not provided or empty, error (we are in case it is mandatory)
		if (!GETPOST('token', 'alpha') || GETPOST('token', 'alpha') == 'notrequired') {
			if (GETPOST('uploadform', 'int')) {
				dol_syslog("--- Access to ".(empty($_SERVER["REQUEST_METHOD"]) ? '' : $_SERVER["REQUEST_METHOD"].' ').$_SERVER["PHP_SELF"]." refused. File size too large or not provided.");
				$langs->loadLangs(array("errors", "install"));
				print $langs->trans("ErrorFileSizeTooLarge").' ';
				print $langs->trans("ErrorGoBackAndCorrectParameters");
				die;
			} else {
				if (defined('CSRFCHECK_WITH_TOKEN')) {
					dol_syslog("--- Access to ".(empty($_SERVER["REQUEST_METHOD"]) ? '' : $_SERVER["REQUEST_METHOD"].' ').$_SERVER["PHP_SELF"]." refused by CSRF protection (CSRFCHECK_WITH_TOKEN protection) in main.inc.php. Token not provided.", LOG_WARNING);
					print "Access to a page that needs a token (constant CSRFCHECK_WITH_TOKEN is defined) is refused by CSRF protection in main.inc.php. Token not provided.\n";
				} else {
					dol_syslog("--- Access to ".(empty($_SERVER["REQUEST_METHOD"]) ? '' : $_SERVER["REQUEST_METHOD"].' ').$_SERVER["PHP_SELF"]." refused by CSRF protection (POST method or GET with a sensible value for 'action' parameter) in main.inc.php. Token not provided.", LOG_WARNING);
					print "Access to this page this way (POST method or GET with a sensible value for 'action' parameter) is refused by CSRF protection in main.inc.php. Token not provided.\n";
					print "If you access your server behind a proxy using url rewriting and the parameter is provided by caller, you might check that all HTTP header are propagated (or add the line \$dolibarr_nocsrfcheck=1 into your conf.php file or MAIN_SECURITY_CSRF_WITH_TOKEN to 0";
					if (!empty($conf->global->MAIN_SECURITY_CSRF_WITH_TOKEN)) {
						print " instead of ".$conf->global->MAIN_SECURITY_CSRF_WITH_TOKEN;
					}
					print " into setup).\n";
				}
				die;
			}
		}
	}

	$sessiontokenforthisurl = (empty($_SESSION['token']) ? '' : $_SESSION['token']);
	// TODO Get the sessiontokenforthisurl into the array of session token
	if (GETPOSTISSET('token') && GETPOST('token') != 'notrequired' && GETPOST('token', 'alpha') != $sessiontokenforthisurl) {
		dol_syslog("--- Access to ".(empty($_SERVER["REQUEST_METHOD"]) ? '' : $_SERVER["REQUEST_METHOD"].' ').$_SERVER["PHP_SELF"]." refused by CSRF protection (invalid token), so we disable POST and some GET parameters - referer=".$_SERVER['HTTP_REFERER'].", action=".GETPOST('action', 'aZ09').", _GET|POST['token']=".GETPOST('token', 'alpha').", _SESSION['token']=".$_SESSION['token'], LOG_WARNING);
		//print 'Unset POST by CSRF protection in main.inc.php.';	// Do not output anything because this create problems when using the BACK button on browsers.
		setEventMessages('SecurityTokenHasExpiredSoActionHasBeenCanceledPleaseRetry', null, 'warnings');
		$savid = null;
		if (isset($_POST['id'])) {
			$savid = ((int) $_POST['id']);
		}
		unset($_POST);
		//unset($_POST['action']); unset($_POST['massaction']);
		//unset($_POST['confirm']); unset($_POST['confirmmassaction']);
		unset($_GET['confirm']);
		unset($_GET['action']);
		unset($_GET['confirmmassaction']);
		unset($_GET['massaction']);
		unset($_GET['token']);			// TODO Make a redirect if we have a token in url to remove it ?
		if (isset($savid)) {
			$_POST['id'] = ((int) $savid);
		}
	}

	// Note: There is another CSRF protection into the filefunc.inc.php
}

// Disable modules (this must be after session_start and after conf has been loaded)
if (GETPOSTISSET('disablemodules')) {
	$_SESSION["disablemodules"] = GETPOST('disablemodules', 'alpha');
}
if (!empty($_SESSION["disablemodules"])) {
	$modulepartkeys = array('css', 'js', 'tabs', 'triggers', 'login', 'substitutions', 'menus', 'theme', 'sms', 'tpl', 'barcode', 'models', 'societe', 'hooks', 'dir', 'syslog', 'tpllinkable', 'contactelement', 'moduleforexternal');

	$disabled_modules = explode(',', $_SESSION["disablemodules"]);
	foreach ($disabled_modules as $module) {
		if ($module) {
			if (empty($conf->$module)) {
				$conf->$module = new stdClass(); // To avoid warnings
			}
			$conf->$module->enabled = false;
			foreach ($modulepartkeys as $modulepartkey) {
				unset($conf->modules_parts[$modulepartkey][$module]);
			}
			if ($module == 'fournisseur') {		// Special case
				$conf->supplier_order->enabled = 0;
				$conf->supplier_invoice->enabled = 0;
			}
		}
	}
}

// Set current modulepart
$modulepart = explode("/", $_SERVER["PHP_SELF"]);
if (is_array($modulepart) && count($modulepart) > 0) {
	foreach ($conf->modules as $module) {
		if (in_array($module, $modulepart)) {
			$conf->modulepart = $module;
			break;
		}
	}
}

/*
 * Phase authentication / login
 */
$login = '';
if (!defined('NOLOGIN')) {
	// $authmode lists the different method of identification to be tested in order of preference.
	// Example: 'http', 'dolibarr', 'ldap', 'http,forceuser', '...'

	if (defined('MAIN_AUTHENTICATION_MODE')) {
		$dolibarr_main_authentication = constant('MAIN_AUTHENTICATION_MODE');
	} else {
		// Authentication mode
		if (empty($dolibarr_main_authentication)) {
			$dolibarr_main_authentication = 'http,dolibarr';
		}
		// Authentication mode: forceuser
		if ($dolibarr_main_authentication == 'forceuser' && empty($dolibarr_auto_user)) {
			$dolibarr_auto_user = 'auto';
		}
	}
	// Set authmode
	$authmode = explode(',', $dolibarr_main_authentication);

	// No authentication mode
	if (!count($authmode)) {
		$langs->load('main');
		dol_print_error('', $langs->trans("ErrorConfigParameterNotDefined", 'dolibarr_main_authentication'));
		exit;
	}

	// If login request was already post, we retrieve login from the session
	// Call module if not realized that his request.
	// At the end of this phase, the variable $login is defined.
	$resultFetchUser = '';
	$test = true;
	if (!isset($_SESSION["dol_login"])) {
		// It is not already authenticated and it requests the login / password
		include_once DOL_DOCUMENT_ROOT.'/core/lib/security2.lib.php';

		$dol_dst_observed = GETPOST("dst_observed", 'int', 3);
		$dol_dst_first = GETPOST("dst_first", 'int', 3);
		$dol_dst_second = GETPOST("dst_second", 'int', 3);
		$dol_screenwidth = GETPOST("screenwidth", 'int', 3);
		$dol_screenheight = GETPOST("screenheight", 'int', 3);
		$dol_hide_topmenu = GETPOST('dol_hide_topmenu', 'int', 3);
		$dol_hide_leftmenu = GETPOST('dol_hide_leftmenu', 'int', 3);
		$dol_optimize_smallscreen = GETPOST('dol_optimize_smallscreen', 'int', 3);
		$dol_no_mouse_hover = GETPOST('dol_no_mouse_hover', 'int', 3);
		$dol_use_jmobile = GETPOST('dol_use_jmobile', 'int', 3); // 0=default, 1=to say we use app from a webview app, 2=to say we use app from a webview app and keep ajax
		//dol_syslog("POST key=".join(array_keys($_POST),',').' value='.join($_POST,','));

		// If in demo mode, we check we go to home page through the public/demo/index.php page
		if (!empty($dolibarr_main_demo) && $_SERVER['PHP_SELF'] == DOL_URL_ROOT.'/index.php') {  // We ask index page
			if (empty($_SERVER['HTTP_REFERER']) || !preg_match('/public/', $_SERVER['HTTP_REFERER'])) {
				dol_syslog("Call index page from another url than demo page (call is done from page ".$_SERVER['HTTP_REFERER'].")");
				$url = '';
				$url .= ($url ? '&' : '').($dol_hide_topmenu ? 'dol_hide_topmenu='.$dol_hide_topmenu : '');
				$url .= ($url ? '&' : '').($dol_hide_leftmenu ? 'dol_hide_leftmenu='.$dol_hide_leftmenu : '');
				$url .= ($url ? '&' : '').($dol_optimize_smallscreen ? 'dol_optimize_smallscreen='.$dol_optimize_smallscreen : '');
				$url .= ($url ? '&' : '').($dol_no_mouse_hover ? 'dol_no_mouse_hover='.$dol_no_mouse_hover : '');
				$url .= ($url ? '&' : '').($dol_use_jmobile ? 'dol_use_jmobile='.$dol_use_jmobile : '');
				$url = DOL_URL_ROOT.'/public/demo/index.php'.($url ? '?'.$url : '');
				header("Location: ".$url);
				exit;
			}
		}

		// Hooks for security access
		$action = '';
		$hookmanager->initHooks(array('login'));
		$parameters = array();
		$reshook = $hookmanager->executeHooks('beforeLoginAuthentication', $parameters, $user, $action); // Note that $action and $object may have been modified by some hooks
		if ($reshook < 0) {
			$test = false;
			$error++;
		}

		// Verification security graphic code
		if ($test && GETPOST("username", "alpha", 2) && !empty($conf->global->MAIN_SECURITY_ENABLECAPTCHA) && !isset($_SESSION['dol_bypass_antispam'])) {
			$sessionkey = 'dol_antispam_value';
			$ok = (array_key_exists($sessionkey, $_SESSION) === true && (strtolower($_SESSION[$sessionkey]) === strtolower(GETPOST('code', 'restricthtml'))));

			// Check code
			if (!$ok) {
				dol_syslog('Bad value for code, connexion refused');
				// Load translation files required by page
				$langs->loadLangs(array('main', 'errors'));

				$_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorBadValueForCode");
				$test = false;

				// Call trigger for the "security events" log
				$user->trigger_mesg = 'ErrorBadValueForCode - login='.GETPOST("username", "alpha", 2);

				// Call trigger
				$result = $user->call_trigger('USER_LOGIN_FAILED', $user);
				if ($result < 0) {
					$error++;
				}
				// End call triggers

				// Hooks on failed login
				$action = '';
				$hookmanager->initHooks(array('login'));
				$parameters = array('dol_authmode'=>$authmode, 'dol_loginmesg'=>$_SESSION["dol_loginmesg"]);
				$reshook = $hookmanager->executeHooks('afterLoginFailed', $parameters, $user, $action); // Note that $action and $object may have been modified by some hooks
				if ($reshook < 0) {
					$error++;
				}

				// Note: exit is done later
			}
		}

		$allowedmethodtopostusername = 2;
		if (defined('MAIN_AUTHENTICATION_POST_METHOD')) {
			$allowedmethodtopostusername = constant('MAIN_AUTHENTICATION_POST_METHOD');
		}
		$usertotest = (!empty($_COOKIE['login_dolibarr']) ? preg_replace('/[^a-zA-Z0-9_\-]/', '', $_COOKIE['login_dolibarr']) : GETPOST("username", "alpha", $allowedmethodtopostusername));
		$passwordtotest = GETPOST('password', 'none', $allowedmethodtopostusername);
		$entitytotest = (GETPOST('entity', 'int') ? GETPOST('entity', 'int') : (!empty($conf->entity) ? $conf->entity : 1));

		// Define if we received data to test the login.
		$goontestloop = false;
		if (isset($_SERVER["REMOTE_USER"]) && in_array('http', $authmode)) {
			$goontestloop = true;
		}
		if ($dolibarr_main_authentication == 'forceuser' && !empty($dolibarr_auto_user)) {
			$goontestloop = true;
		}
		if (GETPOST("username", "alpha", $allowedmethodtopostusername) || !empty($_COOKIE['login_dolibarr']) || GETPOST('openid_mode', 'alpha', 1)) {
			$goontestloop = true;
		}

		if (!is_object($langs)) { // This can occurs when calling page with NOREQUIRETRAN defined, however we need langs for error messages.
			include_once DOL_DOCUMENT_ROOT.'/core/class/translate.class.php';
			$langs = new Translate("", $conf);
			$langcode = (GETPOST('lang', 'aZ09', 1) ?GETPOST('lang', 'aZ09', 1) : (empty($conf->global->MAIN_LANG_DEFAULT) ? 'auto' : $conf->global->MAIN_LANG_DEFAULT));
			if (defined('MAIN_LANG_DEFAULT')) {
				$langcode = constant('MAIN_LANG_DEFAULT');
			}
			$langs->setDefaultLang($langcode);
		}

		// Validation of login/pass/entity
		// If ok, the variable login will be returned
		// If error, we will put error message in session under the name dol_loginmesg
		if ($test && $goontestloop && (GETPOST('actionlogin', 'aZ09') == 'login' || $dolibarr_main_authentication != 'dolibarr')) {
			$login = checkLoginPassEntity($usertotest, $passwordtotest, $entitytotest, $authmode);
			if ($login === '--bad-login-validity--') {
				$login = '';
			}

			if ($login) {
				$dol_authmode = $conf->authmode; // This properties is defined only when logged, to say what mode was successfully used
				$dol_tz = $_POST["tz"];
				$dol_tz_string = $_POST["tz_string"];
				$dol_tz_string = preg_replace('/\s*\(.+\)$/', '', $dol_tz_string);
				$dol_tz_string = preg_replace('/,/', '/', $dol_tz_string);
				$dol_tz_string = preg_replace('/\s/', '_', $dol_tz_string);
				$dol_dst = 0;
				// Keep $_POST here. Do not use GETPOSTISSET
				if (isset($_POST["dst_first"]) && isset($_POST["dst_second"])) {
					include_once DOL_DOCUMENT_ROOT.'/core/lib/date.lib.php';
					$datenow = dol_now();
					$datefirst = dol_stringtotime($_POST["dst_first"]);
					$datesecond = dol_stringtotime($_POST["dst_second"]);
					if ($datenow >= $datefirst && $datenow < $datesecond) {
						$dol_dst = 1;
					}
				}
				//print $datefirst.'-'.$datesecond.'-'.$datenow.'-'.$dol_tz.'-'.$dol_tzstring.'-'.$dol_dst; exit;
			}

			if (!$login) {
				dol_syslog('Bad password, connexion refused', LOG_DEBUG);
				// Load translation files required by page
				$langs->loadLangs(array('main', 'errors'));

				// Bad password. No authmode has found a good password.
				// We set a generic message if not defined inside function checkLoginPassEntity or subfunctions
				if (empty($_SESSION["dol_loginmesg"])) {
					$_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorBadLoginPassword");
				}

				// Call trigger for the "security events" log
				$user->trigger_mesg = $langs->trans("ErrorBadLoginPassword").' - login='.GETPOST("username", "alpha", 2);

				// Call trigger
				$result = $user->call_trigger('USER_LOGIN_FAILED', $user);
				if ($result < 0) {
					$error++;
				}
				// End call triggers

				// Hooks on failed login
				$action = '';
				$hookmanager->initHooks(array('login'));
				$parameters = array('dol_authmode'=>$dol_authmode, 'dol_loginmesg'=>$_SESSION["dol_loginmesg"]);
				$reshook = $hookmanager->executeHooks('afterLoginFailed', $parameters, $user, $action); // Note that $action and $object may have been modified by some hooks
				if ($reshook < 0) {
					$error++;
				}

				// Note: exit is done in next chapter
			}
		}

		// End test login / passwords
		if (!$login || (in_array('ldap', $authmode) && empty($passwordtotest))) {	// With LDAP we refused empty password because some LDAP are "opened" for anonymous access so connexion is a success.
			// No data to test login, so we show the login page.
			dol_syslog("--- Access to ".(empty($_SERVER["REQUEST_METHOD"]) ? '' : $_SERVER["REQUEST_METHOD"].' ').$_SERVER["PHP_SELF"]." - action=".GETPOST('action', 'aZ09')." - actionlogin=".GETPOST('actionlogin', 'aZ09')." - showing the login form and exit", LOG_INFO);
			if (defined('NOREDIRECTBYMAINTOLOGIN')) {
				return 'ERROR_NOT_LOGGED';
			} else {
				if ($_SERVER["HTTP_USER_AGENT"] == 'securitytest') {
					http_response_code(401); // It makes easier to understand if session was broken during security tests
				}
				dol_loginfunction($langs, $conf, (!empty($mysoc) ? $mysoc : ''));
			}
			exit;
		}

		$resultFetchUser = $user->fetch('', $login, '', 1, ($entitytotest > 0 ? $entitytotest : -1)); // login was retrieved previously when checking password.
		if ($resultFetchUser <= 0) {
			dol_syslog('User not found, connexion refused');
			session_destroy();
			session_set_cookie_params(0, '/', null, (empty($dolibarr_main_force_https) ? false : true), true); // Add tag secure and httponly on session cookie
			session_name($sessionname);
			session_start();

			if ($resultFetchUser == 0) {
				// Load translation files required by page
				$langs->loadLangs(array('main', 'errors'));

				$_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorCantLoadUserFromDolibarrDatabase", $login);

				$user->trigger_mesg = 'ErrorCantLoadUserFromDolibarrDatabase - login='.$login;
			}
			if ($resultFetchUser < 0) {
				$_SESSION["dol_loginmesg"] = $user->error;

				$user->trigger_mesg = $user->error;
			}

			// Call trigger
			$result = $user->call_trigger('USER_LOGIN_FAILED', $user);
			if ($result < 0) {
				$error++;
			}
			// End call triggers


			// Hooks on failed login
			$action = '';
			$hookmanager->initHooks(array('login'));
			$parameters = array('dol_authmode'=>$dol_authmode, 'dol_loginmesg'=>$_SESSION["dol_loginmesg"]);
			$reshook = $hookmanager->executeHooks('afterLoginFailed', $parameters, $user, $action); // Note that $action and $object may have been modified by some hooks
			if ($reshook < 0) {
				$error++;
			}

			$paramsurl = array();
			if (GETPOST('textbrowser', 'int')) {
				$paramsurl[] = 'textbrowser='.GETPOST('textbrowser', 'int');
			}
			if (GETPOST('nojs', 'int')) {
				$paramsurl[] = 'nojs='.GETPOST('nojs', 'int');
			}
			if (GETPOST('lang', 'aZ09')) {
				$paramsurl[] = 'lang='.GETPOST('lang', 'aZ09');
			}
			header('Location: '.DOL_URL_ROOT.'/index.php'.(count($paramsurl) ? '?'.implode('&', $paramsurl) : ''));
			exit;
		} else {
			// User is loaded, we may need to change language for him according to its choice
			if (!empty($user->conf->MAIN_LANG_DEFAULT)) {
				$langs->setDefaultLang($user->conf->MAIN_LANG_DEFAULT);
			}
		}
	} else {
		// We are already into an authenticated session
		$login = $_SESSION["dol_login"];
		$entity = isset($_SESSION["dol_entity"]) ? $_SESSION["dol_entity"] : 0;
		dol_syslog("- This is an already logged session. _SESSION['dol_login']=".$login." _SESSION['dol_entity']=".$entity, LOG_DEBUG);

		$resultFetchUser = $user->fetch('', $login, '', 1, ($entity > 0 ? $entity : -1));
		if ($resultFetchUser <= 0) {
			// Account has been removed after login
			dol_syslog("Can't load user even if session logged. _SESSION['dol_login']=".$login, LOG_WARNING);
			session_destroy();
			session_set_cookie_params(0, '/', null, (empty($dolibarr_main_force_https) ? false : true), true); // Add tag secure and httponly on session cookie
			session_name($sessionname);
			session_start();

			if ($resultFetchUser == 0) {
				// Load translation files required by page
				$langs->loadLangs(array('main', 'errors'));

				$_SESSION["dol_loginmesg"] = $langs->transnoentitiesnoconv("ErrorCantLoadUserFromDolibarrDatabase", $login);

				$user->trigger_mesg = 'ErrorCantLoadUserFromDolibarrDatabase - login='.$login;
			}
			if ($resultFetchUser < 0) {
				$_SESSION["dol_loginmesg"] = $user->error;

				$user->trigger_mesg = $user->error;
			}

			// Call trigger
			$result = $user->call_trigger('USER_LOGIN_FAILED', $user);
			if ($result < 0) {
				$error++;
			}
			// End call triggers

			// Hooks on failed login
			$action = '';
			$hookmanager->initHooks(array('login'));
			$parameters = array('dol_authmode'=>$dol_authmode, 'dol_loginmesg'=>$_SESSION["dol_loginmesg"]);
			$reshook = $hookmanager->executeHooks('afterLoginFailed', $parameters, $user, $action); // Note that $action and $object may have been modified by some hooks
			if ($reshook < 0) {
				$error++;
			}

			$paramsurl = array();
			if (GETPOST('textbrowser', 'int')) {
				$paramsurl[] = 'textbrowser='.GETPOST('textbrowser', 'int');
			}
			if (GETPOST('nojs', 'int')) {
				$paramsurl[] = 'nojs='.GETPOST('nojs', 'int');
			}
			if (GETPOST('lang', 'aZ09')) {
				$paramsurl[] = 'lang='.GETPOST('lang', 'aZ09');
			}
			header('Location: '.DOL_URL_ROOT.'/index.php'.(count($paramsurl) ? '?'.implode('&', $paramsurl) : ''));
			exit;
		} else {
			// Initialize technical object to manage hooks of page. Note that conf->hooks_modules contains array of hook context
			$hookmanager->initHooks(array('main'));

			// Code for search criteria persistence.
			if (!empty($_GET['save_lastsearch_values'])) {    // We must use $_GET here
				$relativepathstring = preg_replace('/\?.*$/', '', $_SERVER["HTTP_REFERER"]);
				$relativepathstring = preg_replace('/^https?:\/\/[^\/]*/', '', $relativepathstring); // Get full path except host server
				// Clean $relativepathstring
				if (constant('DOL_URL_ROOT')) {
					$relativepathstring = preg_replace('/^'.preg_quote(constant('DOL_URL_ROOT'), '/').'/', '', $relativepathstring);
				}
				$relativepathstring = preg_replace('/^\//', '', $relativepathstring);
				$relativepathstring = preg_replace('/^custom\//', '', $relativepathstring);
				//var_dump($relativepathstring);

				// We click on a link that leave a page we have to save search criteria, contextpage, limit and page. We save them from tmp to no tmp
				if (!empty($_SESSION['lastsearch_values_tmp_'.$relativepathstring])) {
					$_SESSION['lastsearch_values_'.$relativepathstring] = $_SESSION['lastsearch_values_tmp_'.$relativepathstring];
					unset($_SESSION['lastsearch_values_tmp_'.$relativepathstring]);
				}
				if (!empty($_SESSION['lastsearch_contextpage_tmp_'.$relativepathstring])) {
					$_SESSION['lastsearch_contextpage_'.$relativepathstring] = $_SESSION['lastsearch_contextpage_tmp_'.$relativepathstring];
					unset($_SESSION['lastsearch_contextpage_tmp_'.$relativepathstring]);
				}
				if (!empty($_SESSION['lastsearch_page_tmp_'.$relativepathstring]) && $_SESSION['lastsearch_page_tmp_'.$relativepathstring] > 0) {
					$_SESSION['lastsearch_page_'.$relativepathstring] = $_SESSION['lastsearch_page_tmp_'.$relativepathstring];
					unset($_SESSION['lastsearch_page_tmp_'.$relativepathstring]);
				}
				if (!empty($_SESSION['lastsearch_limit_tmp_'.$relativepathstring]) && $_SESSION['lastsearch_limit_tmp_'.$relativepathstring] != $conf->liste_limit) {
					$_SESSION['lastsearch_limit_'.$relativepathstring] = $_SESSION['lastsearch_limit_tmp_'.$relativepathstring];
					unset($_SESSION['lastsearch_limit_tmp_'.$relativepathstring]);
				}
			}

			$action = '';
			$reshook = $hookmanager->executeHooks('updateSession', array(), $user, $action);
			if ($reshook < 0) {
				setEventMessages($hookmanager->error, $hookmanager->errors, 'errors');
			}
		}
	}

	// Is it a new session that has started ?
	// If we are here, this means authentication was successfull.
	if (!isset($_SESSION["dol_login"])) {
		// New session for this login has started.
		$error = 0;

		// Store value into session (values always stored)
		$_SESSION["dol_login"] = $user->login;
		$_SESSION["dol_authmode"] = isset($dol_authmode) ? $dol_authmode : '';
		$_SESSION["dol_tz"] = isset($dol_tz) ? $dol_tz : '';
		$_SESSION["dol_tz_string"] = isset($dol_tz_string) ? $dol_tz_string : '';
		$_SESSION["dol_dst"] = isset($dol_dst) ? $dol_dst : '';
		$_SESSION["dol_dst_observed"] = isset($dol_dst_observed) ? $dol_dst_observed : '';
		$_SESSION["dol_dst_first"] = isset($dol_dst_first) ? $dol_dst_first : '';
		$_SESSION["dol_dst_second"] = isset($dol_dst_second) ? $dol_dst_second : '';
		$_SESSION["dol_screenwidth"] = isset($dol_screenwidth) ? $dol_screenwidth : '';
		$_SESSION["dol_screenheight"] = isset($dol_screenheight) ? $dol_screenheight : '';
		$_SESSION["dol_company"] = getDolGlobalString("MAIN_INFO_SOCIETE_NOM");
		$_SESSION["dol_entity"] = $conf->entity;
		// Store value into session (values stored only if defined)
		if (!empty($dol_hide_topmenu)) {
			$_SESSION['dol_hide_topmenu'] = $dol_hide_topmenu;
		}
		if (!empty($dol_hide_leftmenu)) {
			$_SESSION['dol_hide_leftmenu'] = $dol_hide_leftmenu;
		}
		if (!empty($dol_optimize_smallscreen)) {
			$_SESSION['dol_optimize_smallscreen'] = $dol_optimize_smallscreen;
		}
		if (!empty($dol_no_mouse_hover)) {
			$_SESSION['dol_no_mouse_hover'] = $dol_no_mouse_hover;
		}
		if (!empty($dol_use_jmobile)) {
			$_SESSION['dol_use_jmobile'] = $dol_use_jmobile;
		}

		dol_syslog("This is a new started user session. _SESSION['dol_login']=".$_SESSION["dol_login"]." Session id=".session_id());

		$db->begin();

		$user->update_last_login_date();

		$loginfo = 'TZ='.$_SESSION["dol_tz"].';TZString='.$_SESSION["dol_tz_string"].';Screen='.$_SESSION["dol_screenwidth"].'x'.$_SESSION["dol_screenheight"];

		// Call triggers for the "security events" log
		$user->trigger_mesg = $loginfo;

		// Call trigger
		$result = $user->call_trigger('USER_LOGIN', $user);
		if ($result < 0) {
			$error++;
		}
		// End call triggers

		// Hooks on successfull login
		$action = '';
		$hookmanager->initHooks(array('login'));
		$parameters = array('dol_authmode'=>$dol_authmode, 'dol_loginfo'=>$loginfo);
		$reshook = $hookmanager->executeHooks('afterLogin', $parameters, $user, $action); // Note that $action and $object may have been modified by some hooks
		if ($reshook < 0) {
			$error++;
		}

		if ($error) {
			$db->rollback();
			session_destroy();
			dol_print_error($db, 'Error in some triggers USER_LOGIN or in some hooks afterLogin');
			exit;
		} else {
			$db->commit();
		}

		// Change landing page if defined.
		$landingpage = (empty($user->conf->MAIN_LANDING_PAGE) ? (empty($conf->global->MAIN_LANDING_PAGE) ? '' : $conf->global->MAIN_LANDING_PAGE) : $user->conf->MAIN_LANDING_PAGE);
		if (!empty($landingpage)) {    // Example: /index.php
			$newpath = dol_buildpath($landingpage, 1);
			if ($_SERVER["PHP_SELF"] != $newpath) {   // not already on landing page (avoid infinite loop)
				header('Location: '.$newpath);
				exit;
			}
		}
	}


	// If user admin, we force the rights-based modules
	if ($user->admin) {
		$user->rights->user->user->lire = 1;
		$user->rights->user->user->creer = 1;
		$user->rights->user->user->password = 1;
		$user->rights->user->user->supprimer = 1;
		$user->rights->user->self->creer = 1;
		$user->rights->user->self->password = 1;

		//Required if advanced permissions are used with MAIN_USE_ADVANCED_PERMS
		if (!empty($conf->global->MAIN_USE_ADVANCED_PERMS)) {
			if (empty($user->rights->user->user_advance)) {
				$user->rights->user->user_advance = new stdClass(); // To avoid warnings
			}
			if (empty($user->rights->user->self_advance)) {
				$user->rights->user->self_advance = new stdClass(); // To avoid warnings
			}
			if (empty($user->rights->user->group_advance)) {
				$user->rights->user->group_advance = new stdClass(); // To avoid warnings
			}

			$user->rights->user->user_advance->readperms = 1;
			$user->rights->user->user_advance->write = 1;
			$user->rights->user->self_advance->readperms = 1;
			$user->rights->user->self_advance->writeperms = 1;
			$user->rights->user->group_advance->read = 1;
			$user->rights->user->group_advance->readperms = 1;
			$user->rights->user->group_advance->write = 1;
			$user->rights->user->group_advance->delete = 1;
		}
	}

	/*
	 * Overwrite some configs globals (try to avoid this and have code to use instead $user->conf->xxx)
	 */

	// Set liste_limit
	if (isset($user->conf->MAIN_SIZE_LISTE_LIMIT)) {
		$conf->liste_limit = $user->conf->MAIN_SIZE_LISTE_LIMIT; // Can be 0
	}
	if (isset($user->conf->PRODUIT_LIMIT_SIZE)) {
		$conf->product->limit_size = $user->conf->PRODUIT_LIMIT_SIZE; // Can be 0
	}

	// Replace conf->css by personalized value if theme not forced
	if (empty($conf->global->MAIN_FORCETHEME) && !empty($user->conf->MAIN_THEME)) {
		$conf->theme = $user->conf->MAIN_THEME;
		$conf->css = "/theme/".$conf->theme."/style.css.php";
	}
}


// Case forcing style from url
if (GETPOST('theme', 'aZ09')) {
	$conf->theme = GETPOST('theme', 'aZ09', 1);
	$conf->css = "/theme/".$conf->theme."/style.css.php";
}

// Set javascript option
if (GETPOST('nojs', 'int')) {  // If javascript was not disabled on URL
	$conf->use_javascript_ajax = 0;
} else {
	if (!empty($user->conf->MAIN_DISABLE_JAVASCRIPT)) {
		$conf->use_javascript_ajax = !$user->conf->MAIN_DISABLE_JAVASCRIPT;
	}
}

// Set MAIN_OPTIMIZEFORTEXTBROWSER for user (must be after login part)
if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER) && !empty($user->conf->MAIN_OPTIMIZEFORTEXTBROWSER)) {
	$conf->global->MAIN_OPTIMIZEFORTEXTBROWSER = $user->conf->MAIN_OPTIMIZEFORTEXTBROWSER;
}

// set MAIN_OPTIMIZEFORCOLORBLIND for user
$conf->global->MAIN_OPTIMIZEFORCOLORBLIND = empty($user->conf->MAIN_OPTIMIZEFORCOLORBLIND) ? '' : $user->conf->MAIN_OPTIMIZEFORCOLORBLIND;

// Set terminal output option according to conf->browser.
if (GETPOST('dol_hide_leftmenu', 'int') || !empty($_SESSION['dol_hide_leftmenu'])) {
	$conf->dol_hide_leftmenu = 1;
}
if (GETPOST('dol_hide_topmenu', 'int') || !empty($_SESSION['dol_hide_topmenu'])) {
	$conf->dol_hide_topmenu = 1;
}
if (GETPOST('dol_optimize_smallscreen', 'int') || !empty($_SESSION['dol_optimize_smallscreen'])) {
	$conf->dol_optimize_smallscreen = 1;
}
if (GETPOST('dol_no_mouse_hover', 'int') || !empty($_SESSION['dol_no_mouse_hover'])) {
	$conf->dol_no_mouse_hover = 1;
}
if (GETPOST('dol_use_jmobile', 'int') || !empty($_SESSION['dol_use_jmobile'])) {
	$conf->dol_use_jmobile = 1;
}
if (!empty($conf->browser->layout) && $conf->browser->layout != 'classic') {
	$conf->dol_no_mouse_hover = 1;
}
if ((!empty($conf->browser->layout) && $conf->browser->layout == 'phone')
	|| (!empty($_SESSION['dol_screenwidth']) && $_SESSION['dol_screenwidth'] < 400)
	|| (!empty($_SESSION['dol_screenheight']) && $_SESSION['dol_screenheight'] < 400)
) {
	$conf->dol_optimize_smallscreen = 1;
}
// Replace themes bugged with jmobile with eldy
if (!empty($conf->dol_use_jmobile) && in_array($conf->theme, array('bureau2crea', 'cameleo', 'amarok'))) {
	$conf->theme = 'eldy';
	$conf->css = "/theme/".$conf->theme."/style.css.php";
}

if (!defined('NOREQUIRETRAN')) {
	if (!GETPOST('lang', 'aZ09')) {	// If language was not forced on URL
		// If user has chosen its own language
		if (!empty($user->conf->MAIN_LANG_DEFAULT)) {
			// If different than current language
			//print ">>>".$langs->getDefaultLang()."-".$user->conf->MAIN_LANG_DEFAULT;
			if ($langs->getDefaultLang() != $user->conf->MAIN_LANG_DEFAULT) {
				$langs->setDefaultLang($user->conf->MAIN_LANG_DEFAULT);
			}
		}
	}
}

if (!defined('NOLOGIN')) {
	// If the login is not recovered, it is identified with an account that does not exist.
	// Hacking attempt?
	if (!$user->login) {
		accessforbidden();
	}

	// Check if user is active
	if ($user->statut < 1) {
		// If not active, we refuse the user
		$langs->loadLangs(array("errors", "other"));
		dol_syslog("Authentication KO as login is disabled", LOG_NOTICE);
		accessforbidden($langs->trans("ErrorLoginDisabled"));
		exit;
	}

	// Load permissions
	$user->getrights();
}

dol_syslog("--- Access to ".(empty($_SERVER["REQUEST_METHOD"]) ? '' : $_SERVER["REQUEST_METHOD"].' ').$_SERVER["PHP_SELF"].' - action='.GETPOST('action', 'aZ09').', massaction='.GETPOST('massaction', 'aZ09').(defined('NOTOKENRENEWAL') ? ' NOTOKENRENEWAL='.constant('NOTOKENRENEWAL') : ''), LOG_NOTICE);
//Another call for easy debugg
//dol_syslog("Access to ".$_SERVER["PHP_SELF"].' '.$_SERVER["HTTP_REFERER"].' GET='.join(',',array_keys($_GET)).'->'.join(',',$_GET).' POST:'.join(',',array_keys($_POST)).'->'.join(',',$_POST));

// Load main languages files
if (!defined('NOREQUIRETRAN')) {
	// Load translation files required by page
	$langs->loadLangs(array('main', 'dict'));
}

// Define some constants used for style of arrays
$bc = array(0=>'class="impair"', 1=>'class="pair"');
$bcdd = array(0=>'class="drag drop oddeven"', 1=>'class="drag drop oddeven"');
$bcnd = array(0=>'class="nodrag nodrop nohover"', 1=>'class="nodrag nodrop nohoverpair"'); // Used for tr to add new lines
$bctag = array(0=>'class="impair tagtr"', 1=>'class="pair tagtr"');

// Define messages variables
$mesg = ''; $warning = ''; $error = 0;
// deprecated, see setEventMessages() and dol_htmloutput_events()
$mesgs = array(); $warnings = array(); $errors = array();

// Constants used to defined number of lines in textarea
if (empty($conf->browser->firefox)) {
	define('ROWS_1', 1);
	define('ROWS_2', 2);
	define('ROWS_3', 3);
	define('ROWS_4', 4);
	define('ROWS_5', 5);
	define('ROWS_6', 6);
	define('ROWS_7', 7);
	define('ROWS_8', 8);
	define('ROWS_9', 9);
} else {
	define('ROWS_1', 0);
	define('ROWS_2', 1);
	define('ROWS_3', 2);
	define('ROWS_4', 3);
	define('ROWS_5', 4);
	define('ROWS_6', 5);
	define('ROWS_7', 6);
	define('ROWS_8', 7);
	define('ROWS_9', 8);
}

$heightforframes = 50;

// Init menu manager
if (!defined('NOREQUIREMENU')) {
	if (empty($user->socid)) {    // If internal user or not defined
		$conf->standard_menu = (empty($conf->global->MAIN_MENU_STANDARD_FORCED) ? (empty($conf->global->MAIN_MENU_STANDARD) ? 'eldy_menu.php' : $conf->global->MAIN_MENU_STANDARD) : $conf->global->MAIN_MENU_STANDARD_FORCED);
	} else {
		// If external user
		$conf->standard_menu = (empty($conf->global->MAIN_MENUFRONT_STANDARD_FORCED) ? (empty($conf->global->MAIN_MENUFRONT_STANDARD) ? 'eldy_menu.php' : $conf->global->MAIN_MENUFRONT_STANDARD) : $conf->global->MAIN_MENUFRONT_STANDARD_FORCED);
	}

	// Load the menu manager (only if not already done)
	$file_menu = $conf->standard_menu;
	if (GETPOST('menu', 'alpha')) {
		$file_menu = GETPOST('menu', 'alpha'); // example: menu=eldy_menu.php
	}
	if (!class_exists('MenuManager')) {
		$menufound = 0;
		$dirmenus = array_merge(array("/core/menus/"), (array) $conf->modules_parts['menus']);
		foreach ($dirmenus as $dirmenu) {
			$menufound = dol_include_once($dirmenu."standard/".$file_menu);
			if (class_exists('MenuManager')) {
				break;
			}
		}
		if (!class_exists('MenuManager')) {	// If failed to include, we try with standard eldy_menu.php
			dol_syslog("You define a menu manager '".$file_menu."' that can not be loaded.", LOG_WARNING);
			$file_menu = 'eldy_menu.php';
			include_once DOL_DOCUMENT_ROOT."/core/menus/standard/".$file_menu;
		}
	}
	$menumanager = new MenuManager($db, empty($user->socid) ? 0 : 1);
	$menumanager->loadMenu();
}



// Functions

if (!function_exists("llxHeader")) {
	/**
	 *	Show HTML header HTML + BODY + Top menu + left menu + DIV
	 *
	 * @param 	string 			$head				Optionnal head lines
	 * @param 	string 			$title				HTML title
	 * @param	string			$help_url			Url links to help page
	 * 		                            			Syntax is: For a wiki page: EN:EnglishPage|FR:FrenchPage|ES:SpanishPage
	 *                                  			For other external page: http://server/url
	 * @param	string			$target				Target to use on links
	 * @param 	int    			$disablejs			More content into html header
	 * @param 	int    			$disablehead		More content into html header
	 * @param 	array|string  	$arrayofjs			Array of complementary js files
	 * @param 	array|string  	$arrayofcss			Array of complementary css files
	 * @param	string			$morequerystring	Query string to add to the link "print" to get same parameters (use only if autodetect fails)
	 * @param   string  		$morecssonbody      More CSS on body tag. For example 'classforhorizontalscrolloftabs'.
	 * @param	string			$replacemainareaby	Replace call to main_area() by a print of this string
	 * @param	int				$disablenofollow	Disable the "nofollow" on page
	 * @return	void
	 */
	function llxHeader($head = '', $title = '', $help_url = '', $target = '', $disablejs = 0, $disablehead = 0, $arrayofjs = '', $arrayofcss = '', $morequerystring = '', $morecssonbody = '', $replacemainareaby = '', $disablenofollow = 0)
	{
		global $conf;

		// html header
		top_htmlhead($head, $title, $disablejs, $disablehead, $arrayofjs, $arrayofcss, 0, $disablenofollow);

		$tmpcsstouse = 'sidebar-collapse'.($morecssonbody ? ' '.$morecssonbody : '');
		// If theme MD and classic layer, we open the menulayer by default.
		if ($conf->theme == 'md' && !in_array($conf->browser->layout, array('phone', 'tablet')) && empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
			global $mainmenu;
			if ($mainmenu != 'website') {
				$tmpcsstouse = $morecssonbody; // We do not use sidebar-collpase by default to have menuhider open by default.
			}
		}

		if (!empty($conf->global->MAIN_OPTIMIZEFORCOLORBLIND)) {
			$tmpcsstouse .= ' colorblind-'.strip_tags($conf->global->MAIN_OPTIMIZEFORCOLORBLIND);
		}

		//print '<body id="mainbody" class="'.$tmpcsstouse.' bodyColor">'."\n";
		print '<body id="kt_body" class="header-fixed header-tablet-and-mobile-fixed toolbar-enabled toolbar-fixed aside-enabled aside-fixed" style="--kt-toolbar-height:55px;--kt-toolbar-height-tablet-and-mobile:55px">';
		print '  <!--begin::Main-->
		<!--begin::Root-->
		<div class="d-flex flex-column flex-root">
			<!--begin::Page-->
			<div class="page d-flex flex-row flex-column-fluid">
				<!--begin::Aside-->';

		if (empty($conf->dol_hide_leftmenu)) {
			left_menu_metronic('', $help_url, '', '', 1, $title, 1); // $menumanager is retrieved with a global $menumanager inside this function
		}
		// top menu and left menu area
		if (empty($conf->dol_hide_topmenu) || GETPOST('dol_invisible_topmenu', 'int')) {
			top_menu($head, $title, $target, $disablejs, $disablehead, $arrayofjs, $arrayofcss, $morequerystring, $help_url);
		}

		
		print '<perro>';
		// main area
		if ($replacemainareaby) {
			print $replacemainareaby;
			return;
		}
		main_area($title);
		print '</perro>';

		print '</div>';	
		print '</div>';
	}
}


/**
 *  Show HTTP header. Called by top_htmlhead().
 *
 *  @param  string  $contenttype    Content type. For example, 'text/html'
 *  @param	int		$forcenocache	Force disabling of cache for the page
 *  @return	void
 */
function top_httphead($contenttype = 'text/html', $forcenocache = 0)
{
	global $db, $conf, $hookmanager;

	if ($contenttype == 'text/html') {
		header("Content-Type: text/html; charset=".$conf->file->character_set_client);
	} else {
		header("Content-Type: ".$contenttype);
	}

	// Security options
	header("X-Content-Type-Options: nosniff"); // With the nosniff option, if the server says the content is text/html, the browser will render it as text/html (note that most browsers now force this option to on)
	if (!defined('XFRAMEOPTIONS_ALLOWALL')) {
		header("X-Frame-Options: SAMEORIGIN"); // Frames allowed only if on same domain (stop some XSS attacks)
	} else {
		header("X-Frame-Options: ALLOWALL");
	}
	//header("X-XSS-Protection: 1");      		// XSS filtering protection of some browsers (note: use of Content-Security-Policy is more efficient). Disabled as deprecated.
	if (!defined('FORCECSP')) {
		//if (! isset($conf->global->MAIN_HTTP_CONTENT_SECURITY_POLICY))
		//{
		//	// A default security policy that keep usage of js external component like ckeditor, stripe, google, working
		//	$contentsecuritypolicy = "font-src *; img-src *; style-src * 'unsafe-inline' 'unsafe-eval'; default-src 'self' *.stripe.com 'unsafe-inline' 'unsafe-eval'; script-src 'self' *.stripe.com 'unsafe-inline' 'unsafe-eval'; frame-src 'self' *.stripe.com; connect-src 'self';";
		//}
		//else
		$contentsecuritypolicy = empty($conf->global->MAIN_HTTP_CONTENT_SECURITY_POLICY) ? '' : $conf->global->MAIN_HTTP_CONTENT_SECURITY_POLICY;

		if (!is_object($hookmanager)) {
			$hookmanager = new HookManager($db);
		}
		$hookmanager->initHooks(array("main"));

		$parameters = array('contentsecuritypolicy'=>$contentsecuritypolicy);
		$result = $hookmanager->executeHooks('setContentSecurityPolicy', $parameters); // Note that $action and $object may have been modified by some hooks
		if ($result > 0) {
			$contentsecuritypolicy = $hookmanager->resPrint; // Replace CSP
		} else {
			$contentsecuritypolicy .= $hookmanager->resPrint; // Concat CSP
		}

		if (!empty($contentsecuritypolicy)) {
			// For example, to restrict 'script', 'object', 'frames' or 'img' to some domains:
			// script-src https://api.google.com https://anotherhost.com; object-src https://youtube.com; frame-src https://youtube.com; img-src: https://static.example.com
			// For example, to restrict everything to one domain, except 'object', ...:
			// default-src https://cdn.example.net; object-src 'none'
			// For example, to restrict everything to itself except img that can be on other servers:
			// default-src 'self'; img-src *;
			// Pre-existing site that uses too much inline code to fix but wants to ensure resources are loaded only over https and disable plugins:
			// default-src http: https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'
			header("Content-Security-Policy: ".$contentsecuritypolicy);
		}
	} elseif (constant('FORCECSP')) {
		header("Content-Security-Policy: ".constant('FORCECSP'));
	}
	if ($forcenocache) {
		header("Cache-Control: no-cache, no-store, must-revalidate, max-age=0");
	}
}

/**
 * Ouput html header of a page. It calls also top_httphead()
 * This code is also duplicated into security2.lib.php::dol_loginfunction
 *
 * @param 	string 	$head			 Optionnal head lines
 * @param 	string 	$title			 HTML title
 * @param 	int    	$disablejs		 Disable js output
 * @param 	int    	$disablehead	 Disable head output
 * @param 	array  	$arrayofjs		 Array of complementary js files
 * @param 	array  	$arrayofcss		 Array of complementary css files
 * @param 	int    	$disablejmobile	 Disable jmobile (No more used)
 * @param   int     $disablenofollow Disable no follow tag
 * @return	void
 */
function top_htmlhead($head, $title = '', $disablejs = 0, $disablehead = 0, $arrayofjs = '', $arrayofcss = '', $disablejmobile = 0, $disablenofollow = 0)
{
	global $db, $conf, $langs, $user, $mysoc, $hookmanager;

	top_httphead();

	if (empty($conf->css)) {
		$conf->css = '/theme/eldy/style.css.php'; // If not defined, eldy by default
	}

	print '<!doctype html>'."\n";

	print '<html lang="'.substr($langs->defaultlang, 0, 2).'">'."\n";

	//print '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="fr">'."\n";
	if (empty($disablehead)) {
		if (!is_object($hookmanager)) {
			$hookmanager = new HookManager($db);
		}
		$hookmanager->initHooks(array("main"));

		$ext = 'layout='.$conf->browser->layout.'&amp;version='.urlencode(DOL_VERSION);

		print "<head>\n";

		if (GETPOST('dol_basehref', 'alpha')) {
			print '<base href="'.dol_escape_htmltag(GETPOST('dol_basehref', 'alpha')).'">'."\n";
		}

		// Displays meta
		print '<meta charset="utf-8">'."\n";
		print '<meta name="robots" content="noindex'.($disablenofollow ? '' : ',nofollow').'">'."\n"; // Do not index
		print '<meta name="viewport" content="width=device-width, initial-scale=1.0">'."\n"; // Scale for mobile device
		print '<meta name="author" content="Dolibarr Development Team">'."\n";
		if (getDolGlobalInt('MAIN_FEATURES_LEVEL')) {
			print '<meta name="MAIN_FEATURES_LEVEL" content="'.getDolGlobalInt('MAIN_FEATURES_LEVEL').'">'."\n";
		}
		// Favicon
		$favicon = DOL_URL_ROOT.'/theme/dolibarr_256x256_color.png';
		if (!empty($mysoc->logo_squarred_mini)) {
			$favicon = DOL_URL_ROOT.'/viewimage.php?cache=1&modulepart=mycompany&file='.urlencode('logos/thumbs/'.$mysoc->logo_squarred_mini);
		}
		if (!empty($conf->global->MAIN_FAVICON_URL)) {
			$favicon = $conf->global->MAIN_FAVICON_URL;
		}
		if (empty($conf->dol_use_jmobile)) {
			print '<link rel="shortcut icon" type="image/x-icon" href="'.$favicon.'"/>'."\n"; // Not required into an Android webview
		}

		//if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) print '<link rel="top" title="'.$langs->trans("Home").'" href="'.(DOL_URL_ROOT?DOL_URL_ROOT:'/').'">'."\n";
		//if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) print '<link rel="copyright" title="GNU General Public License" href="https://www.gnu.org/copyleft/gpl.html#SEC1">'."\n";
		//if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) print '<link rel="author" title="Dolibarr Development Team" href="https://www.dolibarr.org">'."\n";

		// Mobile appli like icon
		$manifest = DOL_URL_ROOT.'/theme/'.$conf->theme.'/manifest.json.php';
		if (!empty($manifest)) {
			print '<link rel="manifest" href="'.$manifest.'" />'."\n";
		}

		if (!empty($conf->global->THEME_ELDY_TOPMENU_BACK1)) {
			// TODO: use auto theme color switch
			print '<meta name="theme-color" content="rgb('.$conf->global->THEME_ELDY_TOPMENU_BACK1.')">'."\n";
		}

		// Auto refresh page
		if (GETPOST('autorefresh', 'int') > 0) {
			print '<meta http-equiv="refresh" content="'.GETPOST('autorefresh', 'int').'">';
		}

		// Displays title
		$appli = constant('DOL_APPLICATION_TITLE');
		if (!empty($conf->global->MAIN_APPLICATION_TITLE)) {
			$appli = $conf->global->MAIN_APPLICATION_TITLE;
		}

		print '<title>';
		$titletoshow = '';
		if ($title && !empty($conf->global->MAIN_HTML_TITLE) && preg_match('/noapp/', $conf->global->MAIN_HTML_TITLE)) {
			$titletoshow = dol_htmlentities($title);
		} elseif ($title) {
			$titletoshow = dol_htmlentities($appli.' - '.$title);
		} else {
			$titletoshow = dol_htmlentities($appli);
		}

		$parameters = array('title'=>$titletoshow);
		$result = $hookmanager->executeHooks('setHtmlTitle', $parameters); // Note that $action and $object may have been modified by some hooks
		if ($result > 0) {
			$titletoshow = $hookmanager->resPrint; // Replace Title to show
		} else {
			$titletoshow .= $hookmanager->resPrint; // Concat to Title to show
		}

		print $titletoshow;
		print '</title>';

		print "\n";

		if (GETPOST('version', 'int')) {
			$ext = 'version='.GETPOST('version', 'int'); // usefull to force no cache on css/js
		}

		$themeparam = '?lang='.$langs->defaultlang.'&amp;theme='.$conf->theme.(GETPOST('optioncss', 'aZ09') ? '&amp;optioncss='.GETPOST('optioncss', 'aZ09', 1) : '').'&amp;userid='.$user->id.'&amp;entity='.$conf->entity;
		$themeparam .= ($ext ? '&amp;'.$ext : '').'&amp;revision='.getDolGlobalInt("MAIN_IHM_PARAMS_REV");
		if (!empty($_SESSION['dol_resetcache'])) {
			$themeparam .= '&amp;dol_resetcache='.$_SESSION['dol_resetcache'];
		}
		if (GETPOSTISSET('dol_hide_topmenu')) {
			$themeparam .= '&amp;dol_hide_topmenu='.GETPOST('dol_hide_topmenu', 'int');
		}
		if (GETPOSTISSET('dol_hide_leftmenu')) {
			$themeparam .= '&amp;dol_hide_leftmenu='.GETPOST('dol_hide_leftmenu', 'int');
		}
		if (GETPOSTISSET('dol_optimize_smallscreen')) {
			$themeparam .= '&amp;dol_optimize_smallscreen='.GETPOST('dol_optimize_smallscreen', 'int');
		}
		if (GETPOSTISSET('dol_no_mouse_hover')) {
			$themeparam .= '&amp;dol_no_mouse_hover='.GETPOST('dol_no_mouse_hover', 'int');
		}
		if (GETPOSTISSET('dol_use_jmobile')) {
			$themeparam .= '&amp;dol_use_jmobile='.GETPOST('dol_use_jmobile', 'int'); $conf->dol_use_jmobile = GETPOST('dol_use_jmobile', 'int');
		}
		if (GETPOSTISSET('THEME_DARKMODEENABLED')) {
			$themeparam .= '&amp;THEME_DARKMODEENABLED='.GETPOST('THEME_DARKMODEENABLED', 'int');
		}
		if (GETPOSTISSET('THEME_SATURATE_RATIO')) {
			$themeparam .= '&amp;THEME_SATURATE_RATIO='.GETPOST('THEME_SATURATE_RATIO', 'int');
		}

		if (!empty($conf->global->MAIN_ENABLE_FONT_ROBOTO)) {
			print '<link rel="preconnect" href="https://fonts.gstatic.com">'."\n";
			print '<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@200;300;400;500;600&display=swap" rel="stylesheet">'."\n";
		}

		if (!defined('DISABLE_JQUERY') && !$disablejs && $conf->use_javascript_ajax) {
			print '<!-- Includes CSS for JQuery (Ajax library) -->'."\n";
			$jquerytheme = 'base';
			if (!empty($conf->global->MAIN_USE_JQUERY_THEME)) {
				$jquerytheme = $conf->global->MAIN_USE_JQUERY_THEME;
			}
			if (constant('JS_JQUERY_UI')) {
				print '<link rel="stylesheet" type="text/css" href="'.JS_JQUERY_UI.'css/'.$jquerytheme.'/jquery-ui.min.css'.($ext ? '?'.$ext : '').'">'."\n"; // Forced JQuery
			} else {
				print '<link rel="stylesheet" type="text/css" href="'.DOL_URL_ROOT.'/includes/jquery/css/'.$jquerytheme.'/jquery-ui.css'.($ext ? '?'.$ext : '').'">'."\n"; // JQuery
			}
			if (!defined('DISABLE_JQUERY_JNOTIFY')) {
				print '<link rel="stylesheet" type="text/css" href="'.DOL_URL_ROOT.'/includes/jquery/plugins/jnotify/jquery.jnotify-alt.min.css'.($ext ? '?'.$ext : '').'">'."\n"; // JNotify
			}
			if (!defined('DISABLE_SELECT2') && (!empty($conf->global->MAIN_USE_JQUERY_MULTISELECT) || defined('REQUIRE_JQUERY_MULTISELECT'))) {     // jQuery plugin "mutiselect", "multiple-select", "select2"...
				$tmpplugin = empty($conf->global->MAIN_USE_JQUERY_MULTISELECT) ?constant('REQUIRE_JQUERY_MULTISELECT') : $conf->global->MAIN_USE_JQUERY_MULTISELECT;
				print '<link rel="stylesheet" type="text/css" href="'.DOL_URL_ROOT.'/includes/jquery/plugins/'.$tmpplugin.'/dist/css/'.$tmpplugin.'.css'.($ext ? '?'.$ext : '').'">'."\n";
			}
		}

		if (!defined('DISABLE_FONT_AWSOME')) {
			print '<!-- Includes CSS for font awesome -->'."\n";
			print '<link rel="stylesheet" type="text/css" href="'.DOL_URL_ROOT.'/theme/common/fontawesome-5/css/all.min.css'.($ext ? '?'.$ext : '').'">'."\n";
			print '<link rel="stylesheet" type="text/css" href="'.DOL_URL_ROOT.'/theme/common/fontawesome-5/css/v4-shims.min.css'.($ext ? '?'.$ext : '').'">'."\n";
		}

		print '<!-- Includes CSS for Dolibarr theme -->'."\n";
		// Output style sheets (optioncss='print' or ''). Note: $conf->css looks like '/theme/eldy/style.css.php'
		$themepath = dol_buildpath($conf->css, 1);
		$themesubdir = '';
		if (!empty($conf->modules_parts['theme'])) {	// This slow down
			foreach ($conf->modules_parts['theme'] as $reldir) {
				if (file_exists(dol_buildpath($reldir.$conf->css, 0))) {
					$themepath = dol_buildpath($reldir.$conf->css, 1);
					$themesubdir = $reldir;
					break;
				}
			}
		}

		//print 'themepath='.$themepath.' themeparam='.$themeparam;exit;
		print '<link rel="stylesheet" type="text/css" href="'.$themepath.$themeparam.'">'."\n";
		if (!empty($conf->global->MAIN_FIX_FLASH_ON_CHROME)) {
			print '<!-- Includes CSS that does not exists as a workaround of flash bug of chrome -->'."\n".'<link rel="stylesheet" type="text/css" href="filethatdoesnotexiststosolvechromeflashbug">'."\n";
		}

		// CSS forced by modules (relative url starting with /)
		if (!empty($conf->modules_parts['css'])) {
			$arraycss = (array) $conf->modules_parts['css'];
			foreach ($arraycss as $modcss => $filescss) {
				$filescss = (array) $filescss; // To be sure filecss is an array
				foreach ($filescss as $cssfile) {
					if (empty($cssfile)) {
						dol_syslog("Warning: module ".$modcss." declared a css path file into its descriptor that is empty.", LOG_WARNING);
					}
					// cssfile is a relative path
					$urlforcss = dol_buildpath($cssfile, 1);
					if ($urlforcss && $urlforcss != '/') {
						print '<!-- Includes CSS added by module '.$modcss.' -->'."\n".'<link rel="stylesheet" type="text/css" href="'.$urlforcss;
						// We add params only if page is not static, because some web server setup does not return content type text/css if url has parameters, so browser cache is not used.
						if (!preg_match('/\.css$/i', $cssfile)) {
							print $themeparam;
						}
						print '">'."\n";
					} else {
						dol_syslog("Warning: module ".$modcss." declared a css path file for a file we can't find.", LOG_WARNING);
					}
				}
			}
		}
		// CSS forced by page in top_htmlhead call (relative url starting with /)
		if (is_array($arrayofcss)) {
			foreach ($arrayofcss as $cssfile) {
				if (preg_match('/^(http|\/\/)/i', $cssfile)) {
					$urltofile = $cssfile;
				} else {
					$urltofile = dol_buildpath($cssfile, 1);
				}
				print '<!-- Includes CSS added by page -->'."\n".'<link rel="stylesheet" type="text/css" title="default" href="'.$urltofile;
				// We add params only if page is not static, because some web server setup does not return content type text/css if url has parameters and browser cache is not used.
				if (!preg_match('/\.css$/i', $cssfile)) {
					print $themeparam;
				}
				print '">'."\n";
			}
		}

		// Output standard javascript links
		if (!defined('DISABLE_JQUERY') && !$disablejs && !empty($conf->use_javascript_ajax)) {
			// JQuery. Must be before other includes
			print '<!-- Includes JS for JQuery -->'."\n";
			if (defined('JS_JQUERY') && constant('JS_JQUERY')) {
				print '<script src="'.JS_JQUERY.'jquery.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			} else {
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/js/jquery.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}
			if (defined('JS_JQUERY_UI') && constant('JS_JQUERY_UI')) {
				print '<script src="'.JS_JQUERY_UI.'jquery-ui.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			} else {
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/js/jquery-ui.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}
			if (!defined('DISABLE_JQUERY_TABLEDND')) {
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/tablednd/jquery.tablednd.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}
			// jQuery jnotify
			if (empty($conf->global->MAIN_DISABLE_JQUERY_JNOTIFY) && !defined('DISABLE_JQUERY_JNOTIFY')) {
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/jnotify/jquery.jnotify.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}
			// Chart
			if ((empty($conf->global->MAIN_JS_GRAPH) || $conf->global->MAIN_JS_GRAPH == 'chart') && !defined('DISABLE_JS_GRAPH')) {
				print '<script src="'.DOL_URL_ROOT.'/includes/nnnick/chartjs/dist/Chart.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}

			// jQuery jeditable for Edit In Place features
			if (!empty($conf->global->MAIN_USE_JQUERY_JEDITABLE) && !defined('DISABLE_JQUERY_JEDITABLE')) {
				print '<!-- JS to manage editInPlace feature -->'."\n";
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/jeditable/jquery.jeditable.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/jeditable/jquery.jeditable.ui-datepicker.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/jeditable/jquery.jeditable.ui-autocomplete.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
				print '<script>'."\n";
				print 'var urlSaveInPlace = \''.DOL_URL_ROOT.'/core/ajax/saveinplace.php\';'."\n";
				print 'var urlLoadInPlace = \''.DOL_URL_ROOT.'/core/ajax/loadinplace.php\';'."\n";
				print 'var tooltipInPlace = \''.$langs->transnoentities('ClickToEdit').'\';'."\n"; // Added in title attribute of span
				print 'var placeholderInPlace = \'&nbsp;\';'."\n"; // If we put another string than $langs->trans("ClickToEdit") here, nothing is shown. If we put empty string, there is error, Why ?
				print 'var cancelInPlace = \''.$langs->trans("Cancel").'\';'."\n";
				print 'var submitInPlace = \''.$langs->trans('Ok').'\';'."\n";
				print 'var indicatorInPlace = \'<img src="'.DOL_URL_ROOT."/theme/".$conf->theme."/img/working.gif".'">\';'."\n";
				print 'var withInPlace = 300;'; // width in pixel for default string edit
				print '</script>'."\n";
				print '<script src="'.DOL_URL_ROOT.'/core/js/editinplace.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/jeditable/jquery.jeditable.ckeditor.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}
			// jQuery Timepicker
			if (!empty($conf->global->MAIN_USE_JQUERY_TIMEPICKER) || defined('REQUIRE_JQUERY_TIMEPICKER')) {
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/timepicker/jquery-ui-timepicker-addon.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
				print '<script src="'.DOL_URL_ROOT.'/core/js/timepicker.js.php?lang='.$langs->defaultlang.($ext ? '&amp;'.$ext : '').'"></script>'."\n";
			}
			if (!defined('DISABLE_SELECT2') && (!empty($conf->global->MAIN_USE_JQUERY_MULTISELECT) || defined('REQUIRE_JQUERY_MULTISELECT'))) {
				// jQuery plugin "mutiselect", "multiple-select", "select2", ...
				$tmpplugin = empty($conf->global->MAIN_USE_JQUERY_MULTISELECT) ?constant('REQUIRE_JQUERY_MULTISELECT') : $conf->global->MAIN_USE_JQUERY_MULTISELECT;
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/'.$tmpplugin.'/dist/js/'.$tmpplugin.'.full.min.js'.($ext ? '?'.$ext : '').'"></script>'."\n"; // We include full because we need the support of containerCssClass
			}
			if (!defined('DISABLE_MULTISELECT')) {     // jQuery plugin "mutiselect" to select with checkboxes. Can be removed once we have an enhanced search tool
				print '<script src="'.DOL_URL_ROOT.'/includes/jquery/plugins/multiselect/jquery.multi-select.js'.($ext ? '?'.$ext : '').'"></script>'."\n";
			}
		}

		if (!$disablejs && !empty($conf->use_javascript_ajax)) {
			// CKEditor
			if ((!empty($conf->fckeditor->enabled) && (empty($conf->global->FCKEDITOR_EDITORNAME) || $conf->global->FCKEDITOR_EDITORNAME == 'ckeditor') && !defined('DISABLE_CKEDITOR')) || defined('FORCE_CKEDITOR')) {
				print '<!-- Includes JS for CKEditor -->'."\n";
				$pathckeditor = DOL_URL_ROOT.'/includes/ckeditor/ckeditor/';
				$jsckeditor = 'ckeditor.js';
				if (constant('JS_CKEDITOR')) {
					// To use external ckeditor 4 js lib
					$pathckeditor = constant('JS_CKEDITOR');
				}
				print '<script>';
				print '/* enable ckeditor by main.inc.php */';
				print 'var CKEDITOR_BASEPATH = \''.dol_escape_js($pathckeditor).'\';'."\n";
				print 'var ckeditorConfig = \''.dol_escape_js(dol_buildpath($themesubdir.'/theme/'.$conf->theme.'/ckeditor/config.js'.($ext ? '?'.$ext : ''), 1)).'\';'."\n"; // $themesubdir='' in standard usage
				print 'var ckeditorFilebrowserBrowseUrl = \''.DOL_URL_ROOT.'/core/filemanagerdol/browser/default/browser.php?Connector='.DOL_URL_ROOT.'/core/filemanagerdol/connectors/php/connector.php\';'."\n";
				print 'var ckeditorFilebrowserImageBrowseUrl = \''.DOL_URL_ROOT.'/core/filemanagerdol/browser/default/browser.php?Type=Image&Connector='.DOL_URL_ROOT.'/core/filemanagerdol/connectors/php/connector.php\';'."\n";
				print '</script>'."\n";
				print '<script src="'.$pathckeditor.$jsckeditor.($ext ? '?'.$ext : '').'"></script>'."\n";
				print '<script>';
				if (GETPOST('mode', 'aZ09') == 'Full_inline') {
					print 'CKEDITOR.disableAutoInline = false;'."\n";
				} else {
					print 'CKEDITOR.disableAutoInline = true;'."\n";
				}
				print '</script>'."\n";
			}

			// Browser notifications (if NOREQUIREMENU is on, it is mostly a page for popup, so we do not enable notif too. We hide also for public pages).
			if (!defined('NOBROWSERNOTIF') && !defined('NOREQUIREMENU') && !defined('NOLOGIN')) {
				$enablebrowsernotif = false;
				if (!empty($conf->agenda->enabled) && !empty($conf->global->AGENDA_REMINDER_BROWSER)) {
					$enablebrowsernotif = true;
				}
				if ($conf->browser->layout == 'phone') {
					$enablebrowsernotif = false;
				}
				if ($enablebrowsernotif) {
					print '<!-- Includes JS of Dolibarr (browser layout = '.$conf->browser->layout.')-->'."\n";
					print '<script src="'.DOL_URL_ROOT.'/core/js/lib_notification.js.php'.($ext ? '?'.$ext : '').'"></script>'."\n";
				}
			}

			// Global js function
			print '<!-- Includes JS of Dolibarr -->'."\n";
			print '<script src="'.DOL_URL_ROOT.'/core/js/lib_head.js.php?lang='.$langs->defaultlang.($ext ? '&amp;'.$ext : '').'"></script>'."\n";

			// JS forced by modules (relative url starting with /)
			if (!empty($conf->modules_parts['js'])) {		// $conf->modules_parts['js'] is array('module'=>array('file1','file2'))
				$arrayjs = (array) $conf->modules_parts['js'];
				foreach ($arrayjs as $modjs => $filesjs) {
					$filesjs = (array) $filesjs; // To be sure filejs is an array
					foreach ($filesjs as $jsfile) {
						// jsfile is a relative path
						$urlforjs = dol_buildpath($jsfile, 1);
						if ($urlforjs && $urlforjs != '/') {
							print '<!-- Include JS added by module '.$modjs.'-->'."\n".'<script src="'.$urlforjs.((strpos($jsfile, '?') === false) ? '?' : '&amp;').'lang='.$langs->defaultlang.'"></script>'."\n";
						} else {
							dol_syslog("Warning: module ".$modjs." declared a js path file for a file we can't find.", LOG_WARNING);
						}
					}
				}
			}
			// JS forced by page in top_htmlhead (relative url starting with /)
			if (is_array($arrayofjs)) {
				print '<!-- Includes JS added by page -->'."\n";
				foreach ($arrayofjs as $jsfile) {
					if (preg_match('/^(http|\/\/)/i', $jsfile)) {
						print '<script src="'.$jsfile.((strpos($jsfile, '?') === false) ? '?' : '&amp;').'lang='.$langs->defaultlang.'"></script>'."\n";
					} else {
						print '<script src="'.dol_buildpath($jsfile, 1).((strpos($jsfile, '?') === false) ? '?' : '&amp;').'lang='.$langs->defaultlang.'"></script>'."\n";
					}
				}
			}
		}

		if (!empty($head)) {
			print $head."\n";
		}
		if (!empty($conf->global->MAIN_HTML_HEADER)) {
			print $conf->global->MAIN_HTML_HEADER."\n";
		}

		$parameters = array();
		$result = $hookmanager->executeHooks('addHtmlHeader', $parameters); // Note that $action and $object may have been modified by some hooks
		print $hookmanager->resPrint; // Replace Title to show
		print ' <!--begin::Fonts-->
		<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Poppins:300,400,500,600,700">
		<!--end::Fonts-->
		<!--begin::Page Vendor Stylesheets(used by this page)-->
		<link href="/css/principal.css" rel="stylesheet" type="text/css">
		<link href="/metronic8/demo1/assets/plugins/custom/fullcalendar/fullcalendar.bundle.css" rel="stylesheet" type="text/css">
		<link href="/metronic8/demo1/assets/plugins/custom/datatables/datatables.bundle.css" rel="stylesheet" type="text/css">
		<!--end::Page Vendor Stylesheets-->
		<!--begin::Global Stylesheets Bundle(used by all pages)-->
		<link href="/metronic8/demo1/assets/plugins/global/plugins.bundle.css" rel="stylesheet" type="text/css">
		<link href="/metronic8/demo1/assets/css/style.bundle.css" rel="stylesheet" type="text/css">
		<!--end::Global Stylesheets Bundle-->';
		print "</head>\n\n";
	}

	$conf->headerdone = 1; // To tell header was output
}


/**
 *  Show an HTML header + a BODY + The top menu bar
 *
 *  @param      string	$head    			Lines in the HEAD
 *  @param      string	$title   			Title of web page
 *  @param      string	$target  			Target to use in menu links (Example: '' or '_top')
 *	@param		int		$disablejs			Do not output links to js (Ex: qd fonction utilisee par sous formulaire Ajax)
 *	@param		int		$disablehead		Do not output head section
 *	@param		array	$arrayofjs			Array of js files to add in header
 *	@param		array	$arrayofcss			Array of css files to add in header
 *  @param		string	$morequerystring	Query string to add to the link "print" to get same parameters (use only if autodetect fails)
 *  @param      string	$helppagename    	Name of wiki page for help ('' by default).
 * 				     		                Syntax is: For a wiki page: EN:EnglishPage|FR:FrenchPage|ES:SpanishPage
 * 						                    For other external page: http://server/url
 *  @return		void
 */
function top_menu($head, $title = '', $target = '', $disablejs = 0, $disablehead = 0, $arrayofjs = '', $arrayofcss = '', $morequerystring = '', $helppagename = '')
{
	global $user, $conf, $langs, $db;
	global $dolibarr_main_authentication, $dolibarr_main_demo;
	global $hookmanager, $menumanager;

	$searchform = '';

	// Instantiate hooks for external modules
	$hookmanager->initHooks(array('toprightmenu'));

	$toprightmenu = '';

	// For backward compatibility with old modules
	if (empty($conf->headerdone)) {
		$disablenofollow = 0;
		top_htmlhead($head, $title, $disablejs, $disablehead, $arrayofjs, $arrayofcss, 0, $disablenofollow);
		print '<body id="mainbody">';
	}
	//inicia el body  de metronic 
	print '<body id="kt_body" class="header-fixed header-tablet-and-mobile-fixed toolbar-enabled toolbar-fixed aside-enabled aside-fixed bodyColor" style="--kt-toolbar-height:55px;--kt-toolbar-height-tablet-and-mobile:55px">';

	/*
	 * Top menu
	 */
	if ((empty($conf->dol_hide_topmenu) || GETPOST('dol_invisible_topmenu', 'int')) && (!defined('NOREQUIREMENU') || !constant('NOREQUIREMENU'))) {
		if (!isset($form) || !is_object($form)) {
			include_once DOL_DOCUMENT_ROOT.'/core/class/html.form.class.php';
			$form = new Form($db);
		}

		print "\n".'<!-- Start top horizontal -->'."\n";

		// print '<header id="id-top" class="side-nav-vert'.(GETPOST('dol_invisible_topmenu', 'int') ? ' hidden' : '').'">'; // dol_invisible_topmenu differs from dol_hide_topmenu: dol_invisible_topmenu means we output menu but we make it invisible.
		// se comienza el header con wrapper 2036-2046 
		print '<div class="wrapper d-flex flex-column flex-row-fluid" id="kt_wrapper">';
		print '<!--begin::Header-->';
		print '<div id="kt_header" style="" class="header align-items-stretch">';
		print '<!--begin::Container-->';
		print '<div class="container-fluid d-flex align-items-stretch justify-content-between">';
		print ' <!--begin::Wrapper-->
		<div class="d-flex align-items-stretch justify-content-between flex-lg-grow-1">
		<!--begin::Navbar-->
		<div class="d-flex align-items-stretch" id="kt_header_nav">
		<!--begin::Menu wrapper-->';
		print "<div class=\"header-menu align-items-stretch\" data-kt-drawer=\"true\" data-kt-drawer-name=\"header-menu\" data-kt-drawer-activate=\"{default: true, lg: false}\" data-kt-drawer-overlay=\"true\" data-kt-drawer-width=\"{default:'200px', '300px': '250px'}\" data-kt-drawer-direction=\"end\" data-kt-drawer-toggle=\"#kt_header_menu_mobile_toggle\" data-kt-swapper=\"true\" data-kt-swapper-mode=\"prepend\" data-kt-swapper-parent=\"{default: '#kt_body', lg: '#kt_header_nav'}\">";
		print ' <!--begin::Menu-->';
		print '<div class="menu menu-lg-rounded menu-column menu-lg-row menu-state-bg menu-title-gray-700 menu-state-title-primary menu-state-icon-primary menu-state-bullet-primary menu-arrow-gray-400 fw-bold my-5 my-lg-0 align-items-stretch" id="#kt_header_menu" data-kt-menu="true">';
		// // Show menu entries
		// Show menu entries
		// print '<div id="tmenu_tooltip'.(empty($conf->global->MAIN_MENU_INVERT) ? '' : 'invert').'" class="tmenu">'."\n";
		$menumanager->atarget = $target;
		$menumanager->showmenu('top', array('searchform'=>$searchform)); // This contains a \n
		print "</div>\n";
		print "</div>\n";
		print "</div>\n";
		print "</div>\n";
		print "</div>\n";
		print "</div>\n";
		

		// Define link to login card
		$appli = constant('DOL_APPLICATION_TITLE');
		if (!empty($conf->global->MAIN_APPLICATION_TITLE)) {
			$appli = $conf->global->MAIN_APPLICATION_TITLE;
			if (preg_match('/\d\.\d/', $appli)) {
				if (!preg_match('/'.preg_quote(DOL_VERSION).'/', $appli)) {
					$appli .= " (".DOL_VERSION.")"; // If new title contains a version that is different than core
				}
			} else {
				$appli .= " ".DOL_VERSION;
			}
		} else {
			$appli .= " ".DOL_VERSION;
		}

		if (getDolGlobalInt('MAIN_FEATURES_LEVEL')) {
			$appli .= "<br>".$langs->trans("LevelOfFeature").': '.getDolGlobalInt('MAIN_FEATURES_LEVEL');
		}

		$logouttext = '';
		$logouthtmltext = '';
		if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
			//$logouthtmltext=$appli.'<br>';
			if ($_SESSION["dol_authmode"] != 'forceuser' && $_SESSION["dol_authmode"] != 'http') {
				$logouthtmltext .= $langs->trans("Logout").'<br>';

				$logouttext .= '<a accesskey="l" href="'.DOL_URL_ROOT.'/user/logout.php?token='.newToken().'">';
				$logouttext .= img_picto($langs->trans('Logout'), 'sign-out', '', false, 0, 0, '', 'atoplogin');
				$logouttext .= '</a>';
			} else {
				$logouthtmltext .= $langs->trans("NoLogoutProcessWithAuthMode", $_SESSION["dol_authmode"]);
				$logouttext .= img_picto($langs->trans('Logout'), 'sign-out', '', false, 0, 0, '', 'atoplogin opacitymedium');
			}
		}

		print '<div class="login_block usedropdown">'."\n";

		$toprightmenu .= '<div class="login_block_other">';

		// Execute hook printTopRightMenu (hooks should output string like '<div class="login"><a href="">mylink</a></div>')
		$parameters = array();
		$result = $hookmanager->executeHooks('printTopRightMenu', $parameters); // Note that $action and $object may have been modified by some hooks
		if (is_numeric($result)) {
			if ($result == 0) {
				$toprightmenu .= $hookmanager->resPrint; // add
			} else {
				$toprightmenu = $hookmanager->resPrint; // replace
			}
		} else {
			$toprightmenu .= $result; // For backward compatibility
		}

		// Link to module builder
		if (!empty($conf->modulebuilder->enabled)) {
			$text = '<a href="'.DOL_URL_ROOT.'/modulebuilder/index.php?mainmenu=home&leftmenu=admintools" target="modulebuilder">';
			//$text.= img_picto(":".$langs->trans("ModuleBuilder"), 'printer_top.png', 'class="printer"');
			$text .= '<span class="fa fa-bug atoplogin valignmiddle"></span>';
			$text .= '</a>';
			$toprightmenu .= $form->textwithtooltip('', $langs->trans("ModuleBuilder"), 2, 1, $text, 'login_block_elem', 2);
		}

		// Link to print main content area
		if (empty($conf->global->MAIN_PRINT_DISABLELINK) && empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
			$qs = dol_escape_htmltag($_SERVER["QUERY_STRING"]);

			if (isset($_POST) && is_array($_POST)) {
				foreach ($_POST as $key => $value) {
					if ($key !== 'action' && $key !== 'password' && !is_array($value)) {
						$qs .= '&'.$key.'='.urlencode($value);
					}
				}
			}
			$qs .= (($qs && $morequerystring) ? '&' : '').$morequerystring;
			$text = '<a href="'.dol_escape_htmltag($_SERVER["PHP_SELF"]).'?'.$qs.($qs ? '&' : '').'optioncss=print" target="_blank" rel="noopener noreferrer">';
			//$text.= img_picto(":".$langs->trans("PrintContentArea"), 'printer_top.png', 'class="printer"');
			$text .= '<span class="fa fa-print atoplogin valignmiddle"></span>';
			$text .= '</a>';
			$toprightmenu .= $form->textwithtooltip('', $langs->trans("PrintContentArea"), 2, 1, $text, 'login_block_elem', 2);
		}

		// Link to Dolibarr wiki pages
		if (empty($conf->global->MAIN_HELP_DISABLELINK) && empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
			$langs->load("help");

			$helpbaseurl = '';
			$helppage = '';
			$mode = '';
			$helppresent = '';

			if (empty($helppagename)) {
				$helppagename = 'EN:User_documentation|FR:Documentation_utilisateur|ES:Documentación_usuarios';
			} else {
				$helppresent = 'helppresent';
			}

			// Get helpbaseurl, helppage and mode from helppagename and langs
			$arrayres = getHelpParamFor($helppagename, $langs);
			$helpbaseurl = $arrayres['helpbaseurl'];
			$helppage = $arrayres['helppage'];
			$mode = $arrayres['mode'];

			// Link to help pages
			if ($helpbaseurl && $helppage) {
				$text = '';
				$title = $langs->trans($mode == 'wiki' ? 'GoToWikiHelpPage' : 'GoToHelpPage').', ';
				if ($mode == 'wiki') {
					$title .= '<br>'.img_picto('', 'globe', 'class="pictofixedwidth"').$langs->trans("PageWiki").' '.dol_escape_htmltag('"'.strtr($helppage, '_', ' ').'"');
					if ($helppresent) {
						$title .= ' <span class="opacitymedium">('.$langs->trans("DedicatedPageAvailable").')</span>';
					} else {
						$title .= ' <span class="opacitymedium">('.$langs->trans("HomePage").')</span>';
					}
				}
				$text .= '<a class="help" target="_blank" rel="noopener noreferrer" href="';
				if ($mode == 'wiki') {
					$text .= sprintf($helpbaseurl, urlencode(html_entity_decode($helppage)));
				} else {
					$text .= sprintf($helpbaseurl, $helppage);
				}
				$text .= '">';
				$text .= '<span class="fa fa-question-circle atoplogin valignmiddle'.($helppresent ? ' '.$helppresent : '').'"></span>';
				$text .= '<span class="fa fa-long-arrow-alt-up helppresentcircle'.($helppresent ? '' : ' unvisible').'"></span>';
				$text .= '</a>';
				$toprightmenu .= $form->textwithtooltip('', $title, 2, 1, $text, 'login_block_elem', 2);
			}

			// Version
			if (!empty($conf->global->MAIN_SHOWDATABASENAMEINHELPPAGESLINK)) {
				$langs->load('admin');
				$appli .= '<br>'.$langs->trans("Database").': '.$db->database_name;
			}
		}

		if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
			$text = '<span class="aversion"><span class="hideonsmartphone small">'.DOL_VERSION.'</span></span>';
			$toprightmenu .= $form->textwithtooltip('', $appli, 2, 1, $text, 'login_block_elem', 2);
		}

		// Logout link
		$toprightmenu .= $form->textwithtooltip('', $logouthtmltext, 2, 1, $logouttext, 'login_block_elem logout-btn', 2);

		$toprightmenu .= '</div>'; // end div class="login_block_other"


		// Add login user link
		$toprightmenu .= '<div class="login_block_user">';

		// Login name with photo and tooltip
		$mode = -1;
		$toprightmenu .= '<div class="inline-block nowrap"><div class="inline-block login_block_elem login_block_elem_name" style="padding: 0px;">';

		if (!empty($conf->global->MAIN_USE_TOP_MENU_SEARCH_DROPDOWN)) {
			// Add search dropdown
			$toprightmenu .= top_menu_search();
		}

		if (!empty($conf->global->MAIN_USE_TOP_MENU_QUICKADD_DROPDOWN)) {
			// Add search dropdown
			$toprightmenu .= top_menu_quickadd();
		}

		// Add bookmark dropdown
		$toprightmenu .= top_menu_bookmark();

		// Add user dropdown
		$toprightmenu .= top_menu_user();

		$toprightmenu .= '</div></div>';

		$toprightmenu .= '</div>'."\n";


		print $toprightmenu;

		print "</div>\n"; // end div class="login_block"

		print '</header>';

		print '<div style="clear: both;"></div>';
		print "<!-- End top horizontal menu -->\n\n";
	}

	if (empty($conf->dol_hide_leftmenu) && empty($conf->dol_use_jmobile)) {
		print '<!-- Begin div id-container --><div id="id-container" class="id-container">';
	}
}


/**
 * Build the tooltip on user login
 *
 * @param	int			$hideloginname		Hide login name. Show only the image.
 * @param	string		$urllogout			URL for logout (Will use DOL_URL_ROOT.'/user/logout.php?token=...' if empty)
 * @return  string                  		HTML content
 */
function top_menu_user($hideloginname = 0, $urllogout = '')
{
	global $langs, $conf, $db, $hookmanager, $user, $mysoc;
	global $dolibarr_main_authentication, $dolibarr_main_demo;
	global $menumanager;

	$langs->load('companies');

	$userImage = $userDropDownImage = '';
	if (!empty($user->photo)) {
		$userImage          = Form::showphoto('userphoto', $user, 0, 0, 0, 'photouserphoto userphoto', 'small', 0, 1);
		$userDropDownImage  = Form::showphoto('userphoto', $user, 0, 0, 0, 'dropdown-user-image', 'small', 0, 1);
	} else {
		$nophoto = '/public/theme/common/user_anonymous.png';
		if ($user->gender == 'man') {
			$nophoto = '/public/theme/common/user_man.png';
		}
		if ($user->gender == 'woman') {
			$nophoto = '/public/theme/common/user_woman.png';
		}

		$userImage = '<img class="photo photouserphoto userphoto" alt="No photo" src="'.DOL_URL_ROOT.$nophoto.'">';
		$userDropDownImage = '<img class="photo dropdown-user-image" alt="No photo" src="'.DOL_URL_ROOT.$nophoto.'">';
	}

	$dropdownBody = '';
	$dropdownBody .= '<span id="topmenulogincompanyinfo-btn"><i class="fa fa-caret-right"></i> '.$langs->trans("ShowCompanyInfos").'</span>';
	$dropdownBody .= '<div id="topmenulogincompanyinfo" >';

	if ($langs->transcountry("ProfId1", $mysoc->country_code) != '-') {
		$dropdownBody .= '<br><b>'.$langs->transcountry("ProfId1", $mysoc->country_code).'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_SIREN")).'</span>';
	}
	if ($langs->transcountry("ProfId2", $mysoc->country_code) != '-') {
		$dropdownBody .= '<br><b>'.$langs->transcountry("ProfId2", $mysoc->country_code).'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_SIRET")).'</span>';
	}
	if ($langs->transcountry("ProfId3", $mysoc->country_code) != '-') {
		$dropdownBody .= '<br><b>'.$langs->transcountry("ProfId3", $mysoc->country_code).'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_APE")).'</span>';
	}
	if ($langs->transcountry("ProfId4", $mysoc->country_code) != '-') {
		$dropdownBody .= '<br><b>'.$langs->transcountry("ProfId4", $mysoc->country_code).'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_RCS")).'</span>';
	}
	if ($langs->transcountry("ProfId5", $mysoc->country_code) != '-') {
		$dropdownBody .= '<br><b>'.$langs->transcountry("ProfId5", $mysoc->country_code).'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_PROFID5")).'</span>';
	}
	if ($langs->transcountry("ProfId6", $mysoc->country_code) != '-') {
		$dropdownBody .= '<br><b>'.$langs->transcountry("ProfId6", $mysoc->country_code).'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_PROFID6")).'</span>';
	}
	$dropdownBody .= '<br><b>'.$langs->trans("VATIntraShort").'</b>: <span>'.showValueWithClipboardCPButton(getDolGlobalString("MAIN_INFO_TVAINTRA")).'</span>';

	$dropdownBody .= '</div>';

	$dropdownBody .= '<br>';
	$dropdownBody .= '<span id="topmenuloginmoreinfo-btn"><i class="fa fa-caret-right"></i> '.$langs->trans("ShowMoreInfos").'</span>';
	$dropdownBody .= '<div id="topmenuloginmoreinfo" >';

	// login infos
	if (!empty($user->admin)) {
		$dropdownBody .= '<br><b>'.$langs->trans("Administrator").'</b>: '.yn($user->admin);
	}
	if (!empty($user->socid)) {	// Add thirdparty for external users
		$thirdpartystatic = new Societe($db);
		$thirdpartystatic->fetch($user->socid);
		$companylink = ' '.$thirdpartystatic->getNomUrl(2); // picto only of company
		$company = ' ('.$langs->trans("Company").': '.$thirdpartystatic->name.')';
	}
	$type = ($user->socid ? $langs->trans("External").$company : $langs->trans("Internal"));
	$dropdownBody .= '<br><b>'.$langs->trans("Type").':</b> '.$type;
	$dropdownBody .= '<br><b>'.$langs->trans("Status").'</b>: '.$user->getLibStatut(0);
	$dropdownBody .= '<br>';

	$dropdownBody .= '<br><u>'.$langs->trans("Session").'</u>';
	$dropdownBody .= '<br><b>'.$langs->trans("IPAddress").'</b>: '.dol_escape_htmltag($_SERVER["REMOTE_ADDR"]);
	if (!empty($conf->global->MAIN_MODULE_MULTICOMPANY)) {
		$dropdownBody .= '<br><b>'.$langs->trans("ConnectedOnMultiCompany").':</b> '.$conf->entity.' (user entity '.$user->entity.')';
	}
	$dropdownBody .= '<br><b>'.$langs->trans("AuthenticationMode").':</b> '.$_SESSION["dol_authmode"].(empty($dolibarr_main_demo) ? '' : ' (demo)');
	$dropdownBody .= '<br><b>'.$langs->trans("ConnectedSince").':</b> '.dol_print_date($user->datelastlogin, "dayhour", 'tzuser');
	$dropdownBody .= '<br><b>'.$langs->trans("PreviousConnexion").':</b> '.dol_print_date($user->datepreviouslogin, "dayhour", 'tzuser');
	$dropdownBody .= '<br><b>'.$langs->trans("CurrentTheme").':</b> '.$conf->theme;
	$dropdownBody .= '<br><b>'.$langs->trans("CurrentMenuManager").':</b> '.(isset($menumanager) ? $menumanager->name : 'unknown');
	$langFlag = picto_from_langcode($langs->getDefaultLang());
	$dropdownBody .= '<br><b>'.$langs->trans("CurrentUserLanguage").':</b> '.($langFlag ? $langFlag.' ' : '').$langs->getDefaultLang();

	$tz = (int) $_SESSION['dol_tz'] + (int) $_SESSION['dol_dst'];
	$dropdownBody .= '<br><b>'.$langs->trans("ClientTZ").':</b> '.($tz ? ($tz >= 0 ? '+' : '').$tz : '');
	$dropdownBody .= ' ('.$_SESSION['dol_tz_string'].')';
	//$dropdownBody .= ' &nbsp; &nbsp; &nbsp; '.$langs->trans("DaylingSavingTime").': ';
	//if ($_SESSION['dol_dst'] > 0) $dropdownBody .= yn(1);
	//else $dropdownBody .= yn(0);

	$dropdownBody .= '<br><b>'.$langs->trans("Browser").':</b> '.$conf->browser->name.($conf->browser->version ? ' '.$conf->browser->version : '').' ('.dol_escape_htmltag($_SERVER['HTTP_USER_AGENT']).')';
	$dropdownBody .= '<br><b>'.$langs->trans("Layout").':</b> '.$conf->browser->layout;
	$dropdownBody .= '<br><b>'.$langs->trans("Screen").':</b> '.$_SESSION['dol_screenwidth'].' x '.$_SESSION['dol_screenheight'];
	if ($conf->browser->layout == 'phone') {
		$dropdownBody .= '<br><b>'.$langs->trans("Phone").':</b> '.$langs->trans("Yes");
	}
	if (!empty($_SESSION["disablemodules"])) {
		$dropdownBody .= '<br><b>'.$langs->trans("DisabledModules").':</b> <br>'.join(', ', explode(',', $_SESSION["disablemodules"]));
	}
	$dropdownBody .= '</div>';

	// Execute hook
	$parameters = array('user'=>$user, 'langs' => $langs);
	$result = $hookmanager->executeHooks('printTopRightMenuLoginDropdownBody', $parameters); // Note that $action and $object may have been modified by some hooks
	if (is_numeric($result)) {
		if ($result == 0) {
			$dropdownBody .= $hookmanager->resPrint; // add
		} else {
			$dropdownBody = $hookmanager->resPrint; // replace
		}
	}

	if (empty($urllogout)) {
		$urllogout = DOL_URL_ROOT.'/user/logout.php?token='.newToken();
	}
	$logoutLink = '<a accesskey="l" href="'.$urllogout.'" class="button-top-menu-dropdown" ><i class="fa fa-sign-out-alt"></i> '.$langs->trans("Logout").'</a>';
	$profilLink = '<a accesskey="l" href="'.DOL_URL_ROOT.'/user/card.php?id='.$user->id.'" class="button-top-menu-dropdown" ><i class="fa fa-user"></i>  '.$langs->trans("Card").'</a>';


	$profilName = $user->getFullName($langs).' ('.$user->login.')';

	if (!empty($user->admin)) {
		$profilName = '<i class="far fa-star classfortooltip" title="'.$langs->trans("Administrator").'" ></i> '.$profilName;
	}

	// Define version to show
	$appli = constant('DOL_APPLICATION_TITLE');
	if (!empty($conf->global->MAIN_APPLICATION_TITLE)) {
		$appli = $conf->global->MAIN_APPLICATION_TITLE;
		if (preg_match('/\d\.\d/', $appli)) {
			if (!preg_match('/'.preg_quote(DOL_VERSION).'/', $appli)) {
				$appli .= " (".DOL_VERSION.")"; // If new title contains a version that is different than core
			}
		} else {
			$appli .= " ".DOL_VERSION;
		}
	} else {
		$appli .= " ".DOL_VERSION;
	}

	if (empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
		$btnUser = '<!-- div for user link -->
	    <div id="topmenu-login-dropdown" class="userimg atoplogin dropdown user user-menu inline-block">
	        <a href="'.DOL_URL_ROOT.'/user/card.php?id='.$user->id.'" class="dropdown-toggle login-dropdown-a" data-toggle="dropdown">
	            '.$userImage.'<span class="hidden-xs maxwidth200 atoploginusername hideonsmartphone paddingleft">'.dol_trunc($user->firstname ? $user->firstname : $user->login, 10).'</span>
	        </a>
	        <div class="dropdown-menu">
	            <!-- User image -->
	            <div class="user-header">
	                '.$userDropDownImage.'
	                <p>
	                    '.$profilName.'<br>';
		if ($user->datelastlogin) {
			$title = $langs->trans("ConnectedSince").' : '.dol_print_date($user->datelastlogin, "dayhour", 'tzuser');
			if ($user->datepreviouslogin) {
				$title .= '<br>'.$langs->trans("PreviousConnexion").' : '.dol_print_date($user->datepreviouslogin, "dayhour", 'tzuser');
			}
		}
		$btnUser .= '<small class="classfortooltip" title="'.dol_escape_htmltag($title).'" ><i class="fa fa-user-clock"></i> '.dol_print_date($user->datelastlogin, "dayhour", 'tzuser').'</small><br>';
		if ($user->datepreviouslogin) {
			$btnUser .= '<small class="classfortooltip" title="'.dol_escape_htmltag($title).'" ><i class="fa fa-user-clock opacitymedium"></i> '.dol_print_date($user->datepreviouslogin, "dayhour", 'tzuser').'</small><br>';
		}

		//$btnUser .= '<small class="classfortooltip"><i class="fa fa-cog"></i> '.$langs->trans("Version").' '.$appli.'</small>';
		$btnUser .= '
	                </p>
	            </div>

	            <!-- Menu Body -->
	            <div class="user-body">'.$dropdownBody.'</div>

	            <!-- Menu Footer-->
	            <div class="user-footer">
	                <div class="pull-left">
	                    '.$profilLink.'
	                </div>
	                <div class="pull-right">
	                    '.$logoutLink.'
	                </div>
	                <div style="clear:both;"></div>
	            </div>

	        </div>
	    </div>';
	} else {
		$btnUser = '<!-- div for user link -->
	    <div id="topmenu-login-dropdown" class="userimg atoplogin dropdown user user-menu  inline-block">
	    	<a href="'.DOL_URL_ROOT.'/user/card.php?id='.$user->id.'">
	    	'.$userImage.'
	    		<span class="hidden-xs maxwidth200 atoploginusername hideonsmartphone">'.dol_trunc($user->firstname ? $user->firstname : $user->login, 10).'</span>
	    		</a>
		</div>';
	}

	if (!defined('JS_JQUERY_DISABLE_DROPDOWN') && !empty($conf->use_javascript_ajax)) {    // This may be set by some pages that use different jquery version to avoid errors
		$btnUser .= '
        <!-- Code to show/hide the user drop-down -->
        <script>
        $( document ).ready(function() {
            $(document).on("click", function(event) {
                if (!$(event.target).closest("#topmenu-login-dropdown").length) {
					//console.log("close login dropdown");
					// Hide the menus.
                    $("#topmenu-login-dropdown").removeClass("open");
                }
            });
			';

		if ($conf->theme != 'md') {
			$btnUser .= '
	            $("#topmenu-login-dropdown .dropdown-toggle").on("click", function(event) {
					console.log("toggle login dropdown");
					event.preventDefault();
	                $("#topmenu-login-dropdown").toggleClass("open");
	            });

	            $("#topmenulogincompanyinfo-btn").on("click", function() {
	                $("#topmenulogincompanyinfo").slideToggle();
	            });

	            $("#topmenuloginmoreinfo-btn").on("click", function() {
	                $("#topmenuloginmoreinfo").slideToggle();
	            });';
		}

		$btnUser .= '
        });
        </script>
        ';
	}

	return $btnUser;
}

/**
 * Build the tooltip on top menu quick add
 *
 * @return  string                  HTML content
 */
function top_menu_quickadd()
{
	global $langs, $conf, $db, $hookmanager, $user;
	global $menumanager;

	$html = '';
	// Define $dropDownQuickAddHtml
	$dropDownQuickAddHtml = '<div class="dropdown-header bookmark-header center">';
	$dropDownQuickAddHtml .= $langs->trans('QuickAdd');
	$dropDownQuickAddHtml .= '</div>';

	$dropDownQuickAddHtml .= '<div class="quickadd-body dropdown-body">';
	$dropDownQuickAddHtml .= '<div class="quickadd">';
	if (!empty($conf->societe->enabled) && $user->rights->societe->creer) {
		$langs->load("companies");
		$dropDownQuickAddHtml .= '
                <!-- Thirdparty link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/societe/card.php?action=create" title="'.$langs->trans("MenuNewThirdParty").'">
                    '. img_picto('', 'object_company').'<br>'.$langs->trans("ThirdParty").'</a>
                </div>
                ';
	}

	if (!empty($conf->societe->enabled) && $user->rights->societe->contact->creer) {
		$langs->load("companies");
		$dropDownQuickAddHtml .= '
                <!-- Contact link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/contact/card.php?action=create" title="'.$langs->trans("NewContactAddress").'">
                    '. img_picto('', 'object_contact').'<br>'.$langs->trans("Contact").'</a>
                </div>
                ';
	}

	if (!empty($conf->propal->enabled) && $user->rights->propale->creer) {
		$langs->load("propal");
		$dropDownQuickAddHtml .= '
                <!-- Propal link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/comm/propal/card.php?action=create" title="'.$langs->trans("NewPropal").'">
                    '. img_picto('', 'object_propal').'<br>'.$langs->trans("Proposal").'</a>
                </div>
                ';
	}

	if (!empty($conf->commande->enabled) && $user->rights->commande->creer) {
		$langs->load("orders");
		$dropDownQuickAddHtml .= '
                <!-- Order link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/commande/card.php?action=create" title="'.$langs->trans("NewOrder").'">
                    '. img_picto('', 'object_order').'<br>'.$langs->trans("Order").'</a>
                </div>
                ';
	}

	if (!empty($conf->facture->enabled) && $user->rights->facture->creer) {
		$langs->load("bills");
		$dropDownQuickAddHtml .= '
                <!-- Invoice link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/compta/facture/card.php?action=create" title="'.$langs->trans("NewBill").'">
                    '. img_picto('', 'object_bill').'<br>'.$langs->trans("Bill").'</a>
                </div>
                ';
	}

	if (!empty($conf->contrat->enabled) && $user->rights->contrat->creer) {
		$langs->load("contracts");
		$dropDownQuickAddHtml .= '
                <!-- Contract link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/compta/facture/card.php?action=create" title="'.$langs->trans("NewContractSubscription").'">
                    '. img_picto('', 'object_contract').'<br>'.$langs->trans("Contract").'</a>
                </div>
                ';
	}

	if (!empty($conf->supplier_proposal->enabled) && $user->rights->supplier_proposal->creer) {
		$langs->load("supplier_proposal");
		$dropDownQuickAddHtml .= '
                <!-- Supplier proposal link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/supplier_proposal/card.php?action=create" title="'.$langs->trans("NewAskPrice").'">
                    '. img_picto('', 'object_propal').'<br>'.$langs->trans("AskPrice").'</a>
                </div>
                ';
	}

	if ((!empty($conf->fournisseur->enabled) && empty($conf->global->MAIN_USE_NEW_SUPPLIERMOD) && $user->rights->fournisseur->commande->creer) || (!empty($conf->supplier_order->enabled) && $user->rights->supplier_order->creer)) {
		$langs->load("orders");
		$dropDownQuickAddHtml .= '
                <!-- Supplier order link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/fourn/commande/card.php?action=create" title="'.$langs->trans("NewSupplierOrderShort").'">
                    '. img_picto('', 'object_order').'<br>'.$langs->trans("SupplierOrder").'</a>
                </div>
                ';
	}

	if ((!empty($conf->fournisseur->enabled) && empty($conf->global->MAIN_USE_NEW_SUPPLIERMOD) && $user->rights->fournisseur->facture->creer) || (!empty($conf->supplier_invoice->enabled) && $user->rights->supplier_invoice->creer)) {
		$langs->load("bills");
		$dropDownQuickAddHtml .= '
                <!-- Supplier invoice link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/fourn/facture/card.php?action=create" title="'.$langs->trans("NewBill").'">
                    '. img_picto('', 'object_bill').'<br>'.$langs->trans("SupplierBill").'</a>
                </div>
                ';
	}

	if (!empty($conf->product->enabled) && $user->rights->produit->creer) {
		$langs->load("products");
		$dropDownQuickAddHtml .= '
                <!-- Product link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/product/card.php?action=create&amp;type=0" title="'.$langs->trans("NewProduct").'">
                    '. img_picto('', 'object_product').'<br>'.$langs->trans("Product").'</a>
                </div>
                ';
	}

	if (!empty($conf->service->enabled) && $user->rights->service->creer) {
		$langs->load("products");
		$dropDownQuickAddHtml .= '
                <!-- Service link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/product/card.php?action=create&amp;type=1" title="'.$langs->trans("NewService").'">
                    '. img_picto('', 'object_service').'<br>'.$langs->trans("Service").'</a>
                </div>
                ';
	}

	if (!empty($conf->expensereport->enabled) && $user->rights->expensereport->creer) {
		$langs->load("trips");
		$dropDownQuickAddHtml .= '
                <!-- Expense report link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/expensereport/card.php?action=create&fk_user_author='.$user->id.'" title="'.$langs->trans("AddTrip").'">
                    '. img_picto('', 'object_trip').'<br>'.$langs->trans("ExpenseReport").'</a>
                </div>
                ';
	}

	if (!empty($conf->holiday->enabled) && $user->rights->holiday->write) {
		$langs->load("holiday");
		$dropDownQuickAddHtml .= '
                <!-- Holiday link -->
                <div class="quickaddblock center">
                    <a class="quickadddropdown-icon-link" href="'.DOL_URL_ROOT.'/holiday/card.php?action=create&fuserid='.$user->id.'" title="'.$langs->trans("AddCP").'">
                    '. img_picto('', 'object_holiday').'<br>'.$langs->trans("Holidays").'</a>
                </div>
                ';
	}

	// Execute hook printTopRightMenu (hooks should output string like '<div class="login"><a href="">mylink</a></div>')
	$parameters = array();
	$result = $hookmanager->executeHooks('printQuickAddBlock', $parameters); // Note that $action and $object may have been modified by some hooks
	if (is_numeric($result)) {
		if ($result == 0) {
			$dropDownQuickAddHtml .= $hookmanager->resPrint; // add
		} else {
			$dropDownQuickAddHtml = $hookmanager->resPrint; // replace
		}
	} else {
		$dropDownQuickAddHtml .= $result; // For backward compatibility
	}

	$dropDownQuickAddHtml .= '</div>';
	$dropDownQuickAddHtml .= '</div>';

	$html .= '<!-- div for quick add link -->
    <div id="topmenu-quickadd-dropdown" class="atoplogin dropdown inline-block">
        <a class="dropdown-toggle login-dropdown-a" data-toggle="dropdown" href="#" title="'.$langs->trans('QuickAdd').' ('.$langs->trans('QuickAddMenuShortCut').')">
            <i class="fa fa-plus-circle" ></i>
        </a>

        <div class="dropdown-menu">
            '.$dropDownQuickAddHtml.'
        </div>
    </div>';
	$html .= '
        <!-- Code to show/hide the user drop-down -->
        <script>
        $( document ).ready(function() {
            $(document).on("click", function(event) {
                if (!$(event.target).closest("#topmenu-quickadd-dropdown").length) {
                    // Hide the menus.
                    $("#topmenu-quickadd-dropdown").removeClass("open");
                }
            });
            $("#topmenu-quickadd-dropdown .dropdown-toggle").on("click", function(event) {
                openQuickAddDropDown();
            });
            // Key map shortcut
            $(document).keydown(function(e){
                  if( e.which === 76 && e.ctrlKey && e.shiftKey ){
                     console.log(\'control + shift + l : trigger open quick add dropdown\');
                     openQuickAddDropDown();
                  }
            });


            var openQuickAddDropDown = function() {
                event.preventDefault();
                $("#topmenu-quickadd-dropdown").toggleClass("open");
                //$("#top-quickadd-search-input").focus();
            }
        });
        </script>
        ';
	return $html;
}

/**
 * Build the tooltip on top menu bookmark
 *
 * @return  string                  HTML content
 */
function top_menu_bookmark()
{
	global $langs, $conf, $db, $user;

	$html = '';

	// Define $bookmarks
	if (empty($conf->bookmark->enabled) || empty($user->rights->bookmark->lire)) {
		return $html;
	}

	if (!defined('JS_JQUERY_DISABLE_DROPDOWN') && !empty($conf->use_javascript_ajax)) {	    // This may be set by some pages that use different jquery version to avoid errors
		include_once DOL_DOCUMENT_ROOT.'/bookmarks/bookmarks.lib.php';
		$langs->load("bookmarks");

		if (!empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER)) {
			$html .= '<div id="topmenu-bookmark-dropdown" class="dropdown inline-block">';
			$html .= printDropdownBookmarksList();
			$html .= '</div>';
		} else {
			$html .= '<!-- div for bookmark link -->
	        <div id="topmenu-bookmark-dropdown" class="dropdown inline-block">
	            <a class="dropdown-toggle login-dropdown-a" data-toggle="dropdown" href="#" title="'.$langs->trans('Bookmarks').' ('.$langs->trans('BookmarksMenuShortCut').')">
	                <i class="fa fa-star" ></i>
	            </a>
	            <div class="dropdown-menu">
	                '.printDropdownBookmarksList().'
	            </div>
	        </div>';

			$html .= '
	        <!-- Code to show/hide the bookmark drop-down -->
	        <script>
	        $( document ).ready(function() {
	            $(document).on("click", function(event) {
	                if (!$(event.target).closest("#topmenu-bookmark-dropdown").length) {
						//console.log("close bookmark dropdown - we click outside");
	                    // Hide the menus.
	                    $("#topmenu-bookmark-dropdown").removeClass("open");
	                }
	            });

	            $("#topmenu-bookmark-dropdown .dropdown-toggle").on("click", function(event) {
					console.log("toggle bookmark dropdown");
					openBookMarkDropDown();
	            });

	            // Key map shortcut
	            $(document).keydown(function(e){
	                  if( e.which === 77 && e.ctrlKey && e.shiftKey ){
	                     console.log(\'control + shift + m : trigger open bookmark dropdown\');
	                     openBookMarkDropDown();
	                  }
	            });


	            var openBookMarkDropDown = function() {
	                event.preventDefault();
	                $("#topmenu-bookmark-dropdown").toggleClass("open");
	                $("#top-bookmark-search-input").focus();
	            }

	        });
	        </script>
	        ';
		}
	}
	return $html;
}

/**
 * Build the tooltip on top menu tsearch
 *
 * @return  string                  HTML content
 */
function top_menu_search()
{
	global $langs, $conf, $db, $user, $hookmanager;

	$html = '';

	$usedbyinclude = 1;
	$arrayresult = null;
	include DOL_DOCUMENT_ROOT.'/core/ajax/selectsearchbox.php'; // This set $arrayresult

	$defaultAction = '';
	$buttonList = '<div class="dropdown-global-search-button-list" >';
	// Menu with all searchable items
	foreach ($arrayresult as $keyItem => $item) {
		if (empty($defaultAction)) {
			$defaultAction = $item['url'];
		}
		$buttonList .= '<button class="dropdown-item global-search-item" data-target="'.dol_escape_htmltag($item['url']).'" >';
		$buttonList .= $item['text'];
		$buttonList .= '</button>';
	}
	$buttonList .= '</div>';


	$searchInput = '<input name="sall" id="top-global-search-input" class="dropdown-search-input" placeholder="'.$langs->trans('Search').'" autocomplete="off" >';

	$dropDownHtml = '<form id="top-menu-action-search" name="actionsearch" method="GET" action="'.$defaultAction.'" >';

	$dropDownHtml .= '
        <!-- search input -->
        <div class="dropdown-header search-dropdown-header">
            ' . $searchInput.'
        </div>
    ';

	$dropDownHtml .= '
        <!-- Menu Body -->
        <div class="dropdown-body search-dropdown-body">
        '.$buttonList.'
        </div>
        ';

	$dropDownHtml .= '</form>';


	$html .= '<!-- div for Global Search -->
    <div id="topmenu-global-search-dropdown" class="atoplogin dropdown inline-block">
        <a class="dropdown-toggle login-dropdown-a" data-toggle="dropdown" href="#" title="'.$langs->trans('Search').' ('.$langs->trans('SearchMenuShortCut').')">
            <i class="fa fa-search" ></i>
        </a>
        <div class="dropdown-menu dropdown-search">
            '.$dropDownHtml.'
        </div>
    </div>';

	$html .= '
    <!-- Code to show/hide the user drop-down -->
    <script>
    $( document ).ready(function() {

        // prevent submiting form on press ENTER
        $("#top-global-search-input").keydown(function (e) {
            if (e.keyCode == 13) {
                var inputs = $(this).parents("form").eq(0).find(":button");
                if (inputs[inputs.index(this) + 1] != null) {
                    inputs[inputs.index(this) + 1].focus();
                }
                e.preventDefault();
                return false;
            }
        });

        // arrow key nav
        $(document).keydown(function(e) {
			// Get the focused element:
			var $focused = $(":focus");
			if($focused.length && $focused.hasClass("global-search-item")){

           		// UP - move to the previous line
				if (e.keyCode == 38) {
				    e.preventDefault();
					$focused.prev().focus();
				}

				// DOWN - move to the next line
				if (e.keyCode == 40) {
				    e.preventDefault();
					$focused.next().focus();
				}
			}
        });


        // submit form action
        $(".dropdown-global-search-button-list .global-search-item").on("click", function(event) {
            $("#top-menu-action-search").attr("action", $(this).data("target"));
            $("#top-menu-action-search").submit();
        });

        // close drop down
        $(document).on("click", function(event) {
			if (!$(event.target).closest("#topmenu-global-search-dropdown").length) {
				console.log("click close search - we click outside");
                // Hide the menus.
                $("#topmenu-global-search-dropdown").removeClass("open");
            }
        });

        // Open drop down
        $("#topmenu-global-search-dropdown .dropdown-toggle").on("click", function(event) {
			console.log("toggle search dropdown");
            openGlobalSearchDropDown();
        });

        // Key map shortcut
        $(document).keydown(function(e){
              if( e.which === 70 && e.ctrlKey && e.shiftKey ){
                 console.log(\'control + shift + f : trigger open global-search dropdown\');
                 openGlobalSearchDropDown();
              }
        });


        var openGlobalSearchDropDown = function() {
            $("#topmenu-global-search-dropdown").toggleClass("open");
            $("#top-global-search-input").focus();
        }

    });
    </script>
    ';

	return $html;
}

/**
 *  Show left menu bar
 *
 *  @param  array	$menu_array_before 	       	Table of menu entries to show before entries of menu handler. This param is deprectaed and must be provided to ''.
 *  @param  string	$helppagename    	       	Name of wiki page for help ('' by default).
 * 				     		                   	Syntax is: For a wiki page: EN:EnglishPage|FR:FrenchPage|ES:SpanishPage
 * 									         	For other external page: http://server/url
 *  @param  string	$notused             		Deprecated. Used in past to add content into left menu. Hooks can be used now.
 *  @param  array	$menu_array_after           Table of menu entries to show after entries of menu handler
 *  @param  int		$leftmenuwithoutmainarea    Must be set to 1. 0 by default for backward compatibility with old modules.
 *  @param  string	$title                      Title of web page
 *  @param  string  $acceptdelayedhtml          1 if caller request to have html delayed content not returned but saved into global $delayedhtmlcontent (so caller can show it at end of page to avoid flash FOUC effect)
 *  @return	void
 */

function left_menu_metronic($menu_array_before, $helppagename = '', $notused = '', $menu_array_after = '', $leftmenuwithoutmainarea = 0, $title = '', $acceptdelayedhtml = 0){
	print '
	<div id="kt_aside" class="aside aside-dark aside-hoverable" data-kt-drawer="true" data-kt-drawer-name="aside" data-kt-drawer-activate="{default: true, lg: false}" data-kt-drawer-overlay="true" data-kt-drawer-width="{default:\'200px\', \'300px\': \'250px\'}" data-kt-drawer-direction="start" data-kt-drawer-toggle="#kt_aside_mobile_toggle" style="">
                <!--begin::Brand-->
                <div class="aside-logo flex-column-auto" id="kt_aside_logo">
                    <!--begin::Logo-->
                    <a href="/metronic8/demo1/../demo1/index.html">
                        <img alt="Logo" src="/metronic8/demo1/assets/media/logos/logo-1-dark.svg" class="h-25px logo">
                    </a>
                    <!--end::Logo-->
                    <!--begin::Aside toggler-->
                    <div id="kt_aside_toggle" class="btn btn-icon w-auto px-0 btn-active-color-primary aside-toggle" data-kt-toggle="true" data-kt-toggle-state="active" data-kt-toggle-target="body" data-kt-toggle-name="aside-minimize">
                        <!--begin::Svg Icon | path: icons/duotune/arrows/arr079.svg-->
                        <span class="svg-icon svg-icon-1 rotate-180">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                <path opacity="0.5" d="M14.2657 11.4343L18.45 7.25C18.8642 6.83579 18.8642 6.16421 18.45 5.75C18.0358 5.33579 17.3642 5.33579 16.95 5.75L11.4071 11.2929C11.0166 11.6834 11.0166 12.3166 11.4071 12.7071L16.95 18.25C17.3642 18.6642 18.0358 18.6642 18.45 18.25C18.8642 17.8358 18.8642 17.1642 18.45 16.75L14.2657 12.5657C13.9533 12.2533 13.9533 11.7467 14.2657 11.4343Z" fill="currentColor"></path>
                                <path d="M8.2657 11.4343L12.45 7.25C12.8642 6.83579 12.8642 6.16421 12.45 5.75C12.0358 5.33579 11.3642 5.33579 10.95 5.75L5.40712 11.2929C5.01659 11.6834 5.01659 12.3166 5.40712 12.7071L10.95 18.25C11.3642 18.6642 12.0358 18.6642 12.45 18.25C12.8642 17.8358 12.8642 17.1642 12.45 16.75L8.2657 12.5657C7.95328 12.2533 7.95328 11.7467 8.2657 11.4343Z" fill="currentColor"></path>
                            </svg>
                        </span>
                        <!--end::Svg Icon-->
                    </div>
                    <!--end::Aside toggler-->
                </div>
                <!--end::Brand-->
                <!--begin::Aside menu-->
                <div class="aside-menu flex-column-fluid">
                    <!--begin::Aside Menu-->
                    <div class="hover-scroll-overlay-y my-5 my-lg-5" id="kt_aside_menu_wrapper" data-kt-scroll="true" data-kt-scroll-activate="{default: false, lg: true}" data-kt-scroll-height="auto" data-kt-scroll-dependencies="#kt_aside_logo, #kt_aside_footer" data-kt-scroll-wrappers="#kt_aside_menu" data-kt-scroll-offset="0" style="height: 370px;">
                        <!--begin::Menu-->
                        <div class="menu menu-column menu-title-gray-800 menu-state-title-primary menu-state-icon-primary menu-state-bullet-primary menu-arrow-gray-500" id="#kt_aside_menu" data-kt-menu="true" data-kt-menu-expand="false">
                            <div data-kt-menu-trigger="click" class="menu-item here menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen025.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <rect x="2" y="2" width="9" height="9" rx="2" fill="currentColor"></rect>
                                                <rect opacity="0.3" x="13" y="2" width="9" height="9" rx="2" fill="currentColor"></rect>
                                                <rect opacity="0.3" x="13" y="13" width="9" height="9" rx="2" fill="currentColor"></rect>
                                                <rect opacity="0.3" x="2" y="13" width="9" height="9" rx="2" fill="currentColor"></rect>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Dashboards</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg" kt-hidden-height="277" style="display: none; overflow: hidden;">
                                    <div class="menu-item">
                                        <a class="menu-link active" href="/metronic8/demo1/../demo1/index.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Multipurpose</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/ecommerce.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">eCommerce</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/projects.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Projects</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/online-courses.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Online Courses</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/marketing.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Marketing</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/bidding.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Bidding</span>
                                        </a>
                                    </div>
                                    <div class="menu-inner flex-column collapse" id="kt_aside_menu_collapse">
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/logistics.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Logistics</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/delivery.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Delivery</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/website-analytics.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Website Analytics</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/finance-performance.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Finance Performance</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/store-analytics.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Store Analytics</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/social.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Social</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/crypto.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Crypto</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/school.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">School</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/dashboards/podcast.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Podcast</span>
                                            </a>
                                        </div>
                                        <div class="menu-item">
                                            <a class="menu-link" href="/metronic8/demo1/../demo1/landing.html">
                                                <span class="menu-bullet">
                                                    <span class="bullet bullet-dot"></span>
                                                </span>
                                                <span class="menu-title">Landing</span>
                                            </a>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <div class="menu-content">
                                            <a class="btn btn-flex btn-color-success fs-base p-0 ms-2 mb-2 collapsible collapsed rotate" data-bs-toggle="collapse" href="#kt_aside_menu_collapse" data-kt-toggle-text="Show Less">
                                                <span data-kt-toggle-text-target="true">Show 10 More</span>
                                                <!--begin::Svg Icon | path: icons/duotune/arrows/arr082.svg-->
                                                <span class="svg-icon ms-2 svg-icon-3 rotate-180">
                                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                        <path opacity="0.5" d="M12.5657 9.63427L16.75 5.44995C17.1642 5.03574 17.8358 5.03574 18.25 5.44995C18.6642 5.86416 18.6642 6.53574 18.25 6.94995L12.7071 12.4928C12.3166 12.8834 11.6834 12.8834 11.2929 12.4928L5.75 6.94995C5.33579 6.53574 5.33579 5.86416 5.75 5.44995C6.16421 5.03574 6.83579 5.03574 7.25 5.44995L11.4343 9.63427C11.7467 9.94669 12.2533 9.94668 12.5657 9.63427Z" fill="currentColor"></path>
                                                        <path d="M12.5657 15.6343L16.75 11.45C17.1642 11.0357 17.8358 11.0357 18.25 11.45C18.6642 11.8642 18.6642 12.5357 18.25 12.95L12.7071 18.4928C12.3166 18.8834 11.6834 18.8834 11.2929 18.4928L5.75 12.95C5.33579 12.5357 5.33579 11.8642 5.75 11.45C6.16421 11.0357 6.83579 11.0357 7.25 11.45L11.4343 15.6343C11.7467 15.9467 12.2533 15.9467 12.5657 15.6343Z" fill="currentColor"></path>
                                                    </svg>
                                                </span>
                                                <!--end::Svg Icon-->
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="menu-item">
                                <div class="menu-content pt-8 pb-2">
                                    <span class="menu-section text-muted text-uppercase fs-8 ls-1">Crafted</span>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/ecommerce/ecm007.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M21 9V11C21 11.6 20.6 12 20 12H14V8H20C20.6 8 21 8.4 21 9ZM10 8H4C3.4 8 3 8.4 3 9V11C3 11.6 3.4 12 4 12H10V8Z" fill="currentColor"></path>
                                                <path d="M15 2C13.3 2 12 3.3 12 5V8H15C16.7 8 18 6.7 18 5C18 3.3 16.7 2 15 2Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M9 2C10.7 2 12 3.3 12 5V8H9C7.3 8 6 6.7 6 5C6 3.3 7.3 2 9 2ZM4 12V21C4 21.6 4.4 22 5 22H10V12H4ZM20 12V21C20 21.6 19.6 22 19 22H14V12H20Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Pages</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg" kt-hidden-height="390" style="display: none; overflow: hidden;">
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion hover show hiding">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">User Profile</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg show" kt-hidden-height="234" style="">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/user-profile/overview.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Overview</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/user-profile/projects.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Projects</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/user-profile/campaigns.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Campaigns</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/user-profile/documents.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Documents</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/user-profile/followers.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Followers</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/user-profile/activity.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Activity</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Blog</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/blog/home.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Blog Home</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/blog/post.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Blog Post</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Pricing</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/pricing/pricing-1.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Pricing 1</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/pricing/pricing-2.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Pricing 2</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Careers</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/careers/list.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Careers List</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/careers/apply.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Careers Apply</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">FAQ</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/faq/classic.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Classic</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/pages/faq/extended.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Extended</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/pages/about.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">About Us</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/pages/contact.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Contact Us</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/pages/team.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Our Team</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/pages/licenses.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Licenses</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/pages/sitemap.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Sitemap</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/communication/com013.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M6.28548 15.0861C7.34369 13.1814 9.35142 12 11.5304 12H12.4696C14.6486 12 16.6563 13.1814 17.7145 15.0861L19.3493 18.0287C20.0899 19.3618 19.1259 21 17.601 21H6.39903C4.87406 21 3.91012 19.3618 4.65071 18.0287L6.28548 15.0861Z" fill="currentColor"></path>
                                                <rect opacity="0.3" x="8" y="3" width="8" height="8" rx="4" fill="currentColor"></rect>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Account</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg" kt-hidden-height="312" style="display: none; overflow: hidden;">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/overview.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Overview</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/settings.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Settings</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/security.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Security</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/billing.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Billing</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/statements.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Statements</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/referrals.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Referrals</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/api-keys.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">API Keys</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/account/logs.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Logs</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/technology/teh004.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M21 10.7192H3C2.4 10.7192 2 11.1192 2 11.7192C2 12.3192 2.4 12.7192 3 12.7192H6V14.7192C6 18.0192 8.7 20.7192 12 20.7192C15.3 20.7192 18 18.0192 18 14.7192V12.7192H21C21.6 12.7192 22 12.3192 22 11.7192C22 11.1192 21.6 10.7192 21 10.7192Z" fill="currentColor"></path>
                                                <path d="M11.6 21.9192C11.4 21.9192 11.2 21.8192 11 21.7192C10.6 21.4192 10.5 20.7191 10.8 20.3191C11.7 19.1191 12.3 17.8191 12.7 16.3191C12.8 15.8191 13.4 15.4192 13.9 15.6192C14.4 15.7192 14.8 16.3191 14.6 16.8191C14.2 18.5191 13.4 20.1192 12.4 21.5192C12.2 21.7192 11.9 21.9192 11.6 21.9192ZM8.7 19.7192C10.2 18.1192 11 15.9192 11 13.7192V8.71917C11 8.11917 11.4 7.71917 12 7.71917C12.6 7.71917 13 8.11917 13 8.71917V13.0192C13 13.6192 13.4 14.0192 14 14.0192C14.6 14.0192 15 13.6192 15 13.0192V8.71917C15 7.01917 13.7 5.71917 12 5.71917C10.3 5.71917 9 7.01917 9 8.71917V13.7192C9 15.4192 8.4 17.1191 7.2 18.3191C6.8 18.7191 6.9 19.3192 7.3 19.7192C7.5 19.9192 7.7 20.0192 8 20.0192C8.3 20.0192 8.5 19.9192 8.7 19.7192ZM6 16.7192C6.5 16.7192 7 16.2192 7 15.7192V8.71917C7 8.11917 7.1 7.51918 7.3 6.91918C7.5 6.41918 7.2 5.8192 6.7 5.6192C6.2 5.4192 5.59999 5.71917 5.39999 6.21917C5.09999 7.01917 5 7.81917 5 8.71917V15.7192V15.8191C5 16.3191 5.5 16.7192 6 16.7192ZM9 4.71917C9.5 4.31917 10.1 4.11918 10.7 3.91918C11.2 3.81918 11.5 3.21917 11.4 2.71917C11.3 2.21917 10.7 1.91916 10.2 2.01916C9.4 2.21916 8.59999 2.6192 7.89999 3.1192C7.49999 3.4192 7.4 4.11916 7.7 4.51916C7.9 4.81916 8.2 4.91918 8.5 4.91918C8.6 4.91918 8.8 4.81917 9 4.71917ZM18.2 18.9192C18.7 17.2192 19 15.5192 19 13.7192V8.71917C19 5.71917 17.1 3.1192 14.3 2.1192C13.8 1.9192 13.2 2.21917 13 2.71917C12.8 3.21917 13.1 3.81916 13.6 4.01916C15.6 4.71916 17 6.61917 17 8.71917V13.7192C17 15.3192 16.8 16.8191 16.3 18.3191C16.1 18.8191 16.4 19.4192 16.9 19.6192C17 19.6192 17.1 19.6192 17.2 19.6192C17.7 19.6192 18 19.3192 18.2 18.9192Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Authentication</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Basic Layout</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/basic/sign-in.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sign-in</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/basic/sign-up.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sign-up</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/basic/two-steps.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Two-steps</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/basic/password-reset.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Password Reset</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/basic/new-password.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">New Password</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Aside Layout</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/aside/sign-in.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sign-in</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/aside/sign-up.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sign-up</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/aside/two-steps.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Two-steps</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/aside/password-reset.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Password Reset</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/aside/new-password.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">New Password</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Dark Layout</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/dark/sign-in.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sign-in</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/dark/sign-up.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sign-up</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/dark/two-steps.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Two-steps</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/dark/password-reset.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Password Reset</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/layouts/dark/new-password.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">New Password</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/extended/multi-steps-sign-up.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Multi-steps Sign-up</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/extended/two-factor-authentication.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Two Factor Auth</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/extended/free-trial-sign-up.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Free Trial Sign-up</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/extended/coming-soon.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Coming Soon</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/general/welcome.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Welcome Message</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/general/verify-email.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Verify Email</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/general/password-confirmation.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Password Confirmation</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/general/deactivation.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Account Deactivation</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/general/error-404.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Error 404</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/general/error-500.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Error 500</span>
                                        </a>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Email Templates</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/email/verify-email.html" target="blank">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Verify Email</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/email/invitation.html" target="blank">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Account Invitation</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/email/password-reset.html" target="blank">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Password Reset</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/authentication/email/password-change.html" target="blank">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Password Changed</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/art/art009.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M21 18.3V4H20H5C4.4 4 4 4.4 4 5V20C10.9 20 16.7 15.6 19 9.5V18.3C18.4 18.6 18 19.3 18 20C18 21.1 18.9 22 20 22C21.1 22 22 21.1 22 20C22 19.3 21.6 18.6 21 18.3Z" fill="currentColor"></path>
                                                <path d="M22 4C22 2.9 21.1 2 20 2C18.9 2 18 2.9 18 4C18 4.7 18.4 5.29995 18.9 5.69995C18.1 12.6 12.6 18.2 5.70001 18.9C5.30001 18.4 4.7 18 4 18C2.9 18 2 18.9 2 20C2 21.1 2.9 22 4 22C4.8 22 5.39999 21.6 5.79999 20.9C13.8 20.1 20.1 13.7 20.9 5.80005C21.6 5.40005 22 4.8 22 4Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Utilities</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Modals</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                                <span class="menu-link">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">General</span>
                                                    <span class="menu-arrow"></span>
                                                </span>
                                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/general/invite-friends.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Invite Friends</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/general/view-users.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">View Users</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/general/select-users.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Select Users</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/general/upgrade-plan.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Upgrade Plan</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/general/share-earn.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Share &amp; Earn</span>
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                                <span class="menu-link">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Forms</span>
                                                    <span class="menu-arrow"></span>
                                                </span>
                                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/forms/new-target.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">New Target</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/forms/new-card.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">New Card</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/forms/new-address.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">New Address</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/forms/create-api-key.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Create API Key</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/forms/bidding.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Bidding</span>
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                                <span class="menu-link">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Wizards</span>
                                                    <span class="menu-arrow"></span>
                                                </span>
                                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/create-app.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Create App</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/create-campaign.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Create Campaign</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/create-account.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Create Business Acc</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/create-project.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Create Project</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/top-up-wallet.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Top Up Wallet</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/offer-a-deal.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Offer a Deal</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/two-factor-authentication.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Two Factor Auth</span>
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                                <span class="menu-link">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Search</span>
                                                    <span class="menu-arrow"></span>
                                                </span>
                                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/search/users.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Users</span>
                                                        </a>
                                                    </div>
                                                    <div class="menu-item">
                                                        <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/search/select-location.html">
                                                            <span class="menu-bullet">
                                                                <span class="bullet bullet-dot"></span>
                                                            </span>
                                                            <span class="menu-title">Select Location</span>
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Search</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/search/horizontal.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Horizontal</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/search/vertical.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Vertical</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/search/users.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Users</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/search/select-location.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Location</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Wizards</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/horizontal.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Horizontal</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/vertical.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Vertical</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/two-factor-authentication.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Two Factor Auth</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/create-app.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Create App</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/create-campaign.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Create Campaign</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/create-account.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Create Account</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/create-project.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Create Project</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/modals/wizards/top-up-wallet.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Top Up Wallet</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/utilities/wizards/offer-a-deal.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Offer a Deal</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen022.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M11.2929 2.70711C11.6834 2.31658 12.3166 2.31658 12.7071 2.70711L15.2929 5.29289C15.6834 5.68342 15.6834 6.31658 15.2929 6.70711L12.7071 9.29289C12.3166 9.68342 11.6834 9.68342 11.2929 9.29289L8.70711 6.70711C8.31658 6.31658 8.31658 5.68342 8.70711 5.29289L11.2929 2.70711Z" fill="currentColor"></path>
                                                <path d="M11.2929 14.7071C11.6834 14.3166 12.3166 14.3166 12.7071 14.7071L15.2929 17.2929C15.6834 17.6834 15.6834 18.3166 15.2929 18.7071L12.7071 21.2929C12.3166 21.6834 11.6834 21.6834 11.2929 21.2929L8.70711 18.7071C8.31658 18.3166 8.31658 17.6834 8.70711 17.2929L11.2929 14.7071Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M5.29289 8.70711C5.68342 8.31658 6.31658 8.31658 6.70711 8.70711L9.29289 11.2929C9.68342 11.6834 9.68342 12.3166 9.29289 12.7071L6.70711 15.2929C6.31658 15.6834 5.68342 15.6834 5.29289 15.2929L2.70711 12.7071C2.31658 12.3166 2.31658 11.6834 2.70711 11.2929L5.29289 8.70711Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M17.2929 8.70711C17.6834 8.31658 18.3166 8.31658 18.7071 8.70711L21.2929 11.2929C21.6834 11.6834 21.6834 12.3166 21.2929 12.7071L18.7071 15.2929C18.3166 15.6834 17.6834 15.6834 17.2929 15.2929L14.7071 12.7071C14.3166 12.3166 14.3166 11.6834 14.7071 11.2929L17.2929 8.70711Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Widgets</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/widgets/lists.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Lists</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/widgets/statistics.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Statistics</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/widgets/charts.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Charts</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/widgets/mixed.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Mixed</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/widgets/tables.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Tables</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/widgets/feeds.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Feeds</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div class="menu-item">
                                <div class="menu-content pt-8 pb-2">
                                    <span class="menu-section text-muted text-uppercase fs-8 ls-1">Apps</span>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen002.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M4.05424 15.1982C8.34524 7.76818 13.5782 3.26318 20.9282 2.01418C21.0729 1.98837 21.2216 1.99789 21.3618 2.04193C21.502 2.08597 21.6294 2.16323 21.7333 2.26712C21.8372 2.37101 21.9144 2.49846 21.9585 2.63863C22.0025 2.7788 22.012 2.92754 21.9862 3.07218C20.7372 10.4222 16.2322 15.6552 8.80224 19.9462L4.05424 15.1982ZM3.81924 17.3372L2.63324 20.4482C2.58427 20.5765 2.5735 20.7163 2.6022 20.8507C2.63091 20.9851 2.69788 21.1082 2.79503 21.2054C2.89218 21.3025 3.01536 21.3695 3.14972 21.3982C3.28408 21.4269 3.42387 21.4161 3.55224 21.3672L6.66524 20.1802L3.81924 17.3372ZM16.5002 5.99818C16.2036 5.99818 15.9136 6.08615 15.6669 6.25097C15.4202 6.41579 15.228 6.65006 15.1144 6.92415C15.0009 7.19824 14.9712 7.49984 15.0291 7.79081C15.0869 8.08178 15.2298 8.34906 15.4396 8.55884C15.6494 8.76862 15.9166 8.91148 16.2076 8.96935C16.4986 9.02723 16.8002 8.99753 17.0743 8.884C17.3484 8.77046 17.5826 8.5782 17.7474 8.33153C17.9123 8.08486 18.0002 7.79485 18.0002 7.49818C18.0002 7.10035 17.8422 6.71882 17.5609 6.43752C17.2796 6.15621 16.8981 5.99818 16.5002 5.99818Z" fill="currentColor"></path>
                                                <path d="M4.05423 15.1982L2.24723 13.3912C2.15505 13.299 2.08547 13.1867 2.04395 13.0632C2.00243 12.9396 1.9901 12.8081 2.00793 12.679C2.02575 12.5498 2.07325 12.4266 2.14669 12.3189C2.22013 12.2112 2.31752 12.1219 2.43123 12.0582L9.15323 8.28918C7.17353 10.3717 5.4607 12.6926 4.05423 15.1982ZM8.80023 19.9442L10.6072 21.7512C10.6994 21.8434 10.8117 21.9129 10.9352 21.9545C11.0588 21.996 11.1903 22.0083 11.3195 21.9905C11.4486 21.9727 11.5718 21.9252 11.6795 21.8517C11.7872 21.7783 11.8765 21.6809 11.9402 21.5672L15.7092 14.8442C13.6269 16.8245 11.3061 18.5377 8.80023 19.9442ZM7.04023 18.1832L12.5832 12.6402C12.7381 12.4759 12.8228 12.2577 12.8195 12.032C12.8161 11.8063 12.725 11.5907 12.5653 11.4311C12.4057 11.2714 12.1901 11.1803 11.9644 11.1769C11.7387 11.1736 11.5205 11.2583 11.3562 11.4132L5.81323 16.9562L7.04023 18.1832Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Projects</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/list.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">My Projects</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/project.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">View Project</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/targets.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Targets</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/budget.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Budget</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/users.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Users</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/files.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Files</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/activity.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Activity</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/projects/settings.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Settings</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/ecommerce/ecm001.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M18.041 22.041C18.5932 22.041 19.041 21.5932 19.041 21.041C19.041 20.4887 18.5932 20.041 18.041 20.041C17.4887 20.041 17.041 20.4887 17.041 21.041C17.041 21.5932 17.4887 22.041 18.041 22.041Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M6.04095 22.041C6.59324 22.041 7.04095 21.5932 7.04095 21.041C7.04095 20.4887 6.59324 20.041 6.04095 20.041C5.48867 20.041 5.04095 20.4887 5.04095 21.041C5.04095 21.5932 5.48867 22.041 6.04095 22.041Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M7.04095 16.041L19.1409 15.1409C19.7409 15.1409 20.141 14.7409 20.341 14.1409L21.7409 8.34094C21.9409 7.64094 21.4409 7.04095 20.7409 7.04095H5.44095L7.04095 16.041Z" fill="currentColor"></path>
                                                <path d="M19.041 20.041H5.04096C4.74096 20.041 4.34095 19.841 4.14095 19.541C3.94095 19.241 3.94095 18.841 4.14095 18.541L6.04096 14.841L4.14095 4.64095L2.54096 3.84096C2.04096 3.64096 1.84095 3.04097 2.14095 2.54097C2.34095 2.04097 2.94096 1.84095 3.44096 2.14095L5.44096 3.14095C5.74096 3.24095 5.94096 3.54096 5.94096 3.84096L7.94096 14.841C7.94096 15.041 7.94095 15.241 7.84095 15.441L6.54096 18.041H19.041C19.641 18.041 20.041 18.441 20.041 19.041C20.041 19.641 19.641 20.041 19.041 20.041Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">eCommerce</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Catalog</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/catalog/products.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Products</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/catalog/categories.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Categories</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/catalog/add-product.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Add Product</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/catalog/edit-product.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Edit Product</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/catalog/add-category.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Add Category</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/catalog/edit-category.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Edit Category</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Sales</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/sales/listing.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Orders Listing</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/sales/details.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Order Details</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/sales/add-order.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Add Order</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/sales/edit-order.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Edit Order</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Customers</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/customers/listing.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Customer Listing</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/customers/details.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Customer Details</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Reports</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/reports/view.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Products Viewed</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/reports/sales.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Sales</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/reports/returns.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Returns</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/reports/customer-orders.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Customer Orders</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/reports/shipping.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Shipping</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/ecommerce/settings.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Settings</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion mb-1">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/graphs/gra006.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M13 5.91517C15.8 6.41517 18 8.81519 18 11.8152C18 12.5152 17.9 13.2152 17.6 13.9152L20.1 15.3152C20.6 15.6152 21.4 15.4152 21.6 14.8152C21.9 13.9152 22.1 12.9152 22.1 11.8152C22.1 7.01519 18.8 3.11521 14.3 2.01521C13.7 1.91521 13.1 2.31521 13.1 3.01521V5.91517H13Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M19.1 17.0152C19.7 17.3152 19.8 18.1152 19.3 18.5152C17.5 20.5152 14.9 21.7152 12 21.7152C9.1 21.7152 6.50001 20.5152 4.70001 18.5152C4.30001 18.0152 4.39999 17.3152 4.89999 17.0152L7.39999 15.6152C8.49999 16.9152 10.2 17.8152 12 17.8152C13.8 17.8152 15.5 17.0152 16.6 15.6152L19.1 17.0152ZM6.39999 13.9151C6.19999 13.2151 6 12.5152 6 11.8152C6 8.81517 8.2 6.41515 11 5.91515V3.01519C11 2.41519 10.4 1.91519 9.79999 2.01519C5.29999 3.01519 2 7.01517 2 11.8152C2 12.8152 2.2 13.8152 2.5 14.8152C2.7 15.4152 3.4 15.7152 4 15.3152L6.39999 13.9151Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Support Center</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/overview.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Overview</span>
                                        </a>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion mb-1">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Tickets</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/tickets/list.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Tickets List</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/tickets/view.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">View Ticket</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion mb-1">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Tutorials</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/tutorials/list.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Tutorials List</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/tutorials/post.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Tutorial Post</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/faq.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">FAQ</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/licenses.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Licenses</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/support-center/contact.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Contact Us</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion mb-1">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen051.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M20.5543 4.37824L12.1798 2.02473C12.0626 1.99176 11.9376 1.99176 11.8203 2.02473L3.44572 4.37824C3.18118 4.45258 3 4.6807 3 4.93945V13.569C3 14.6914 3.48509 15.8404 4.4417 16.984C5.17231 17.8575 6.18314 18.7345 7.446 19.5909C9.56752 21.0295 11.6566 21.912 11.7445 21.9488C11.8258 21.9829 11.9129 22 12.0001 22C12.0872 22 12.1744 21.983 12.2557 21.9488C12.3435 21.912 14.4326 21.0295 16.5541 19.5909C17.8169 18.7345 18.8277 17.8575 19.5584 16.984C20.515 15.8404 21 14.6914 21 13.569V4.93945C21 4.6807 20.8189 4.45258 20.5543 4.37824Z" fill="currentColor"></path>
                                                <path d="M14.854 11.321C14.7568 11.2282 14.6388 11.1818 14.4998 11.1818H14.3333V10.2272C14.3333 9.61741 14.1041 9.09378 13.6458 8.65628C13.1875 8.21876 12.639 8 12 8C11.361 8 10.8124 8.21876 10.3541 8.65626C9.89574 9.09378 9.66663 9.61739 9.66663 10.2272V11.1818H9.49999C9.36115 11.1818 9.24306 11.2282 9.14583 11.321C9.0486 11.4138 9 11.5265 9 11.6591V14.5227C9 14.6553 9.04862 14.768 9.14583 14.8609C9.24306 14.9536 9.36115 15 9.49999 15H14.5C14.6389 15 14.7569 14.9536 14.8542 14.8609C14.9513 14.768 15 14.6553 15 14.5227V11.6591C15.0001 11.5265 14.9513 11.4138 14.854 11.321ZM13.3333 11.1818H10.6666V10.2272C10.6666 9.87594 10.7969 9.57597 11.0573 9.32743C11.3177 9.07886 11.6319 8.9546 12 8.9546C12.3681 8.9546 12.6823 9.07884 12.9427 9.32743C13.2031 9.57595 13.3333 9.87594 13.3333 10.2272V11.1818Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">User Management</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion mb-1">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Users</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/user-management/users/list.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Users List</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/user-management/users/view.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">View User</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Roles</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/user-management/roles/list.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Roles List</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/user-management/roles/view.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">View Role</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/user-management/permissions.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Permissions</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/electronics/elc002.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M6 21C6 21.6 6.4 22 7 22H17C17.6 22 18 21.6 18 21V20H6V21Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M17 2H7C6.4 2 6 2.4 6 3V20H18V3C18 2.4 17.6 2 17 2Z" fill="currentColor"></path>
                                                <path d="M12 4C11.4 4 11 3.6 11 3V2H13V3C13 3.6 12.6 4 12 4Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Contacts</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/contacts/getting-started.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Getting Started</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/contacts/add-contact.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Add Contact</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/contacts/edit-contact.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Edit Contact</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/contacts/view-contact.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">View Contact</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/ecommerce/ecm002.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M21 10H13V11C13 11.6 12.6 12 12 12C11.4 12 11 11.6 11 11V10H3C2.4 10 2 10.4 2 11V13H22V11C22 10.4 21.6 10 21 10Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M12 12C11.4 12 11 11.6 11 11V3C11 2.4 11.4 2 12 2C12.6 2 13 2.4 13 3V11C13 11.6 12.6 12 12 12Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M18.1 21H5.9C5.4 21 4.9 20.6 4.8 20.1L3 13H21L19.2 20.1C19.1 20.6 18.6 21 18.1 21ZM13 18V15C13 14.4 12.6 14 12 14C11.4 14 11 14.4 11 15V18C11 18.6 11.4 19 12 19C12.6 19 13 18.6 13 18ZM17 18V15C17 14.4 16.6 14 16 14C15.4 14 15 14.4 15 15V18C15 18.6 15.4 19 16 19C16.6 19 17 18.6 17 18ZM9 18V15C9 14.4 8.6 14 8 14C7.4 14 7 14.4 7 15V18C7 18.6 7.4 19 8 19C8.6 19 9 18.6 9 18Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Subscriptions</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/subscriptions/getting-started.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Getting Started</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/subscriptions/list.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Subscription List</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/subscriptions/add.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Add Subscription</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/subscriptions/view.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">View Subscription</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/finance/fin006.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M20 15H4C2.9 15 2 14.1 2 13V7C2 6.4 2.4 6 3 6H21C21.6 6 22 6.4 22 7V13C22 14.1 21.1 15 20 15ZM13 12H11C10.5 12 10 12.4 10 13V16C10 16.5 10.4 17 11 17H13C13.6 17 14 16.6 14 16V13C14 12.4 13.6 12 13 12Z" fill="currentColor"></path>
                                                <path d="M14 6V5H10V6H8V5C8 3.9 8.9 3 10 3H14C15.1 3 16 3.9 16 5V6H14ZM20 15H14V16C14 16.6 13.5 17 13 17H11C10.5 17 10 16.6 10 16V15H4C3.6 15 3.3 14.9 3 14.7V18C3 19.1 3.9 20 5 20H19C20.1 20 21 19.1 21 18V14.7C20.7 14.9 20.4 15 20 15Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Customers</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/customers/getting-started.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Getting Started</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/customers/list.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Customer Listing</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/customers/view.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Customer Details</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/files/fil025.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M14 2H6C4.89543 2 4 2.89543 4 4V20C4 21.1046 4.89543 22 6 22H18C19.1046 22 20 21.1046 20 20V8L14 2Z" fill="currentColor"></path>
                                                <path d="M20 8L14 2V6C14 7.10457 14.8954 8 16 8H20Z" fill="currentColor"></path>
                                                <path d="M10.3629 14.0084L8.92108 12.6429C8.57518 12.3153 8.03352 12.3153 7.68761 12.6429C7.31405 12.9967 7.31405 13.5915 7.68761 13.9453L10.2254 16.3488C10.6111 16.714 11.215 16.714 11.6007 16.3488L16.3124 11.8865C16.6859 11.5327 16.6859 10.9379 16.3124 10.5841C15.9665 10.2565 15.4248 10.2565 15.0789 10.5841L11.4631 14.0084C11.1546 14.3006 10.6715 14.3006 10.3629 14.0084Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">File Manager</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/file-manager/folders.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Folders</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/file-manager/files.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Files</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/file-manager/blank.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Blank Directory</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/file-manager/settings.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Settings</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/finance/fin002.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M22 7H2V11H22V7Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M21 19H3C2.4 19 2 18.6 2 18V6C2 5.4 2.4 5 3 5H21C21.6 5 22 5.4 22 6V18C22 18.6 21.6 19 21 19ZM14 14C14 13.4 13.6 13 13 13H5C4.4 13 4 13.4 4 14C4 14.6 4.4 15 5 15H13C13.6 15 14 14.6 14 14ZM16 15.5C16 16.3 16.7 17 17.5 17H18.5C19.3 17 20 16.3 20 15.5C20 14.7 19.3 14 18.5 14H17.5C16.7 14 16 14.7 16 15.5Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Invoice Manager</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                        <span class="menu-link">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">View Invoices</span>
                                            <span class="menu-arrow"></span>
                                        </span>
                                        <div class="menu-sub menu-sub-accordion menu-active-bg">
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/invoices/view/invoice-1.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Invoice 1</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/invoices/view/invoice-2.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Invoice 2</span>
                                                </a>
                                            </div>
                                            <div class="menu-item">
                                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/invoices/view/invoice-3.html">
                                                    <span class="menu-bullet">
                                                        <span class="bullet bullet-dot"></span>
                                                    </span>
                                                    <span class="menu-title">Invoice 3</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/invoices/create.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Create Invoice</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/communication/com011.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M21 19H3C2.4 19 2 18.6 2 18V6C2 5.4 2.4 5 3 5H21C21.6 5 22 5.4 22 6V18C22 18.6 21.6 19 21 19Z" fill="currentColor"></path>
                                                <path d="M21 5H2.99999C2.69999 5 2.49999 5.10005 2.29999 5.30005L11.2 13.3C11.7 13.7 12.4 13.7 12.8 13.3L21.7 5.30005C21.5 5.10005 21.3 5 21 5Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Inbox</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/inbox/listing.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Messages</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/inbox/compose.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Compose</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/inbox/reply.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">View &amp; Reply</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/communication/com012.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M20 3H4C2.89543 3 2 3.89543 2 5V16C2 17.1046 2.89543 18 4 18H4.5C5.05228 18 5.5 18.4477 5.5 19V21.5052C5.5 22.1441 6.21212 22.5253 6.74376 22.1708L11.4885 19.0077C12.4741 18.3506 13.6321 18 14.8167 18H20C21.1046 18 22 17.1046 22 16V5C22 3.89543 21.1046 3 20 3Z" fill="currentColor"></path>
                                                <rect x="6" y="12" width="7" height="2" rx="1" fill="currentColor"></rect>
                                                <rect x="6" y="7" width="12" height="2" rx="1" fill="currentColor"></rect>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Chat</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/chat/private.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Private Chat</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/chat/group.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Group Chat</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/apps/chat/drawer.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Drawer Chat</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div class="menu-item">
                                <a class="menu-link" href="/metronic8/demo1/../demo1/apps/calendar.html">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen014.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M21 22H3C2.4 22 2 21.6 2 21V5C2 4.4 2.4 4 3 4H21C21.6 4 22 4.4 22 5V21C22 21.6 21.6 22 21 22Z" fill="currentColor"></path>
                                                <path d="M6 6C5.4 6 5 5.6 5 5V3C5 2.4 5.4 2 6 2C6.6 2 7 2.4 7 3V5C7 5.6 6.6 6 6 6ZM11 5V3C11 2.4 10.6 2 10 2C9.4 2 9 2.4 9 3V5C9 5.6 9.4 6 10 6C10.6 6 11 5.6 11 5ZM15 5V3C15 2.4 14.6 2 14 2C13.4 2 13 2.4 13 3V5C13 5.6 13.4 6 14 6C14.6 6 15 5.6 15 5ZM19 5V3C19 2.4 18.6 2 18 2C17.4 2 17 2.4 17 3V5C17 5.6 17.4 6 18 6C18.6 6 19 5.6 19 5Z" fill="currentColor"></path>
                                                <path d="M8.8 13.1C9.2 13.1 9.5 13 9.7 12.8C9.9 12.6 10.1 12.3 10.1 11.9C10.1 11.6 10 11.3 9.8 11.1C9.6 10.9 9.3 10.8 9 10.8C8.8 10.8 8.59999 10.8 8.39999 10.9C8.19999 11 8.1 11.1 8 11.2C7.9 11.3 7.8 11.4 7.7 11.6C7.6 11.8 7.5 11.9 7.5 12.1C7.5 12.2 7.4 12.2 7.3 12.3C7.2 12.4 7.09999 12.4 6.89999 12.4C6.69999 12.4 6.6 12.3 6.5 12.2C6.4 12.1 6.3 11.9 6.3 11.7C6.3 11.5 6.4 11.3 6.5 11.1C6.6 10.9 6.8 10.7 7 10.5C7.2 10.3 7.49999 10.1 7.89999 10C8.29999 9.90003 8.60001 9.80003 9.10001 9.80003C9.50001 9.80003 9.80001 9.90003 10.1 10C10.4 10.1 10.7 10.3 10.9 10.4C11.1 10.5 11.3 10.8 11.4 11.1C11.5 11.4 11.6 11.6 11.6 11.9C11.6 12.3 11.5 12.6 11.3 12.9C11.1 13.2 10.9 13.5 10.6 13.7C10.9 13.9 11.2 14.1 11.4 14.3C11.6 14.5 11.8 14.7 11.9 15C12 15.3 12.1 15.5 12.1 15.8C12.1 16.2 12 16.5 11.9 16.8C11.8 17.1 11.5 17.4 11.3 17.7C11.1 18 10.7 18.2 10.3 18.3C9.9 18.4 9.5 18.5 9 18.5C8.5 18.5 8.1 18.4 7.7 18.2C7.3 18 7 17.8 6.8 17.6C6.6 17.4 6.4 17.1 6.3 16.8C6.2 16.5 6.10001 16.3 6.10001 16.1C6.10001 15.9 6.2 15.7 6.3 15.6C6.4 15.5 6.6 15.4 6.8 15.4C6.9 15.4 7.00001 15.4 7.10001 15.5C7.20001 15.6 7.3 15.6 7.3 15.7C7.5 16.2 7.7 16.6 8 16.9C8.3 17.2 8.6 17.3 9 17.3C9.2 17.3 9.5 17.2 9.7 17.1C9.9 17 10.1 16.8 10.3 16.6C10.5 16.4 10.5 16.1 10.5 15.8C10.5 15.3 10.4 15 10.1 14.7C9.80001 14.4 9.50001 14.3 9.10001 14.3C9.00001 14.3 8.9 14.3 8.7 14.3C8.5 14.3 8.39999 14.3 8.39999 14.3C8.19999 14.3 7.99999 14.2 7.89999 14.1C7.79999 14 7.7 13.8 7.7 13.7C7.7 13.5 7.79999 13.4 7.89999 13.2C7.99999 13 8.2 13 8.5 13H8.8V13.1ZM15.3 17.5V12.2C14.3 13 13.6 13.3 13.3 13.3C13.1 13.3 13 13.2 12.9 13.1C12.8 13 12.7 12.8 12.7 12.6C12.7 12.4 12.8 12.3 12.9 12.2C13 12.1 13.2 12 13.6 11.8C14.1 11.6 14.5 11.3 14.7 11.1C14.9 10.9 15.2 10.6 15.5 10.3C15.8 10 15.9 9.80003 15.9 9.70003C15.9 9.60003 16.1 9.60004 16.3 9.60004C16.5 9.60004 16.7 9.70003 16.8 9.80003C16.9 9.90003 17 10.2 17 10.5V17.2C17 18 16.7 18.4 16.2 18.4C16 18.4 15.8 18.3 15.6 18.2C15.4 18.1 15.3 17.8 15.3 17.5Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Calendar</span>
                                </a>
                            </div>
                            <div class="menu-item">
                                <div class="menu-content pt-8 pb-0">
                                    <span class="menu-section text-muted text-uppercase fs-8 ls-1">Layout</span>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/abstract/abs042.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M18 21.6C16.6 20.4 9.1 20.3 6.3 21.2C5.7 21.4 5.1 21.2 4.7 20.8L2 18C4.2 15.8 10.8 15.1 15.8 15.8C16.2 18.3 17 20.5 18 21.6ZM18.8 2.8C18.4 2.4 17.8 2.20001 17.2 2.40001C14.4 3.30001 6.9 3.2 5.5 2C6.8 3.3 7.4 5.5 7.7 7.7C9 7.9 10.3 8 11.7 8C15.8 8 19.8 7.2 21.5 5.5L18.8 2.8Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M21.2 17.3C21.4 17.9 21.2 18.5 20.8 18.9L18 21.6C15.8 19.4 15.1 12.8 15.8 7.8C18.3 7.4 20.4 6.70001 21.5 5.60001C20.4 7.00001 20.2 14.5 21.2 17.3ZM8 11.7C8 9 7.7 4.2 5.5 2L2.8 4.8C2.4 5.2 2.2 5.80001 2.4 6.40001C2.7 7.40001 3.00001 9.2 3.10001 11.7C3.10001 15.5 2.40001 17.6 2.10001 18C3.20001 16.9 5.3 16.2 7.8 15.8C8 14.2 8 12.7 8 11.7Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Toolbars</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/toolbars/toolbar-1.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Toolbar 1</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/toolbars/toolbar-2.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Toolbar 2</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/toolbars/toolbar-3.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Toolbar 3</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/toolbars/toolbar-4.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Toolbar 4</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/toolbars/toolbar-5.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Toolbar 5</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/toolbars/no-toolbar.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">No Toolbar</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div data-kt-menu-trigger="click" class="menu-item menu-accordion">
                                <span class="menu-link">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen009.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path opacity="0.3" d="M21 22H14C13.4 22 13 21.6 13 21V3C13 2.4 13.4 2 14 2H21C21.6 2 22 2.4 22 3V21C22 21.6 21.6 22 21 22Z" fill="currentColor"></path>
                                                <path d="M10 22H3C2.4 22 2 21.6 2 21V3C2 2.4 2.4 2 3 2H10C10.6 2 11 2.4 11 3V21C11 21.6 10.6 22 10 22Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Aside</span>
                                    <span class="menu-arrow"></span>
                                </span>
                                <div class="menu-sub menu-sub-accordion menu-active-bg">
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/aside/light.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Light Skin</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/aside/font-icons.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Font Icons</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/aside/minimized.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Minimized</span>
                                        </a>
                                    </div>
                                    <div class="menu-item">
                                        <a class="menu-link" href="/metronic8/demo1/../demo1/layouts/aside/only-header.html">
                                            <span class="menu-bullet">
                                                <span class="bullet bullet-dot"></span>
                                            </span>
                                            <span class="menu-title">Only Header</span>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div class="menu-item">
                                <a class="menu-link" href="/metronic8/demo1/../demo1/layout-builder.html" title="" data-bs-toggle="tooltip" data-bs-trigger="hover" data-bs-dismiss="click" data-bs-placement="right" data-bs-original-title="Build your layout and export HTML for server side integration">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/general/gen019.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M17.5 11H6.5C4 11 2 9 2 6.5C2 4 4 2 6.5 2H17.5C20 2 22 4 22 6.5C22 9 20 11 17.5 11ZM15 6.5C15 7.9 16.1 9 17.5 9C18.9 9 20 7.9 20 6.5C20 5.1 18.9 4 17.5 4C16.1 4 15 5.1 15 6.5Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M17.5 22H6.5C4 22 2 20 2 17.5C2 15 4 13 6.5 13H17.5C20 13 22 15 22 17.5C22 20 20 22 17.5 22ZM4 17.5C4 18.9 5.1 20 6.5 20C7.9 20 9 18.9 9 17.5C9 16.1 7.9 15 6.5 15C5.1 15 4 16.1 4 17.5Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Layout Builder</span>
                                </a>
                            </div>
                            <div class="menu-item">
                                <div class="menu-content">
                                    <div class="separator mx-1 my-4"></div>
                                </div>
                            </div>
                            <div class="menu-item">
                                <a class="menu-link" href="/metronic8/demo1/../demo1/documentation/getting-started/changelog.html">
                                    <span class="menu-icon">
                                        <!--begin::Svg Icon | path: icons/duotune/coding/cod003.svg-->
                                        <span class="svg-icon svg-icon-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                                <path d="M16.95 18.9688C16.75 18.9688 16.55 18.8688 16.35 18.7688C15.85 18.4688 15.75 17.8688 16.05 17.3688L19.65 11.9688L16.05 6.56876C15.75 6.06876 15.85 5.46873 16.35 5.16873C16.85 4.86873 17.45 4.96878 17.75 5.46878L21.75 11.4688C21.95 11.7688 21.95 12.2688 21.75 12.5688L17.75 18.5688C17.55 18.7688 17.25 18.9688 16.95 18.9688ZM7.55001 18.7688C8.05001 18.4688 8.15 17.8688 7.85 17.3688L4.25001 11.9688L7.85 6.56876C8.15 6.06876 8.05001 5.46873 7.55001 5.16873C7.05001 4.86873 6.45 4.96878 6.15 5.46878L2.15 11.4688C1.95 11.7688 1.95 12.2688 2.15 12.5688L6.15 18.5688C6.35 18.8688 6.65 18.9688 6.95 18.9688C7.15 18.9688 7.35001 18.8688 7.55001 18.7688Z" fill="currentColor"></path>
                                                <path opacity="0.3" d="M10.45 18.9687C10.35 18.9687 10.25 18.9687 10.25 18.9687C9.75 18.8687 9.35 18.2688 9.55 17.7688L12.55 5.76878C12.65 5.26878 13.25 4.8687 13.75 5.0687C14.25 5.1687 14.65 5.76878 14.45 6.26878L11.45 18.2688C11.35 18.6688 10.85 18.9687 10.45 18.9687Z" fill="currentColor"></path>
                                            </svg>
                                        </span>
                                        <!--end::Svg Icon-->
                                    </span>
                                    <span class="menu-title">Changelog v8.0.38</span>
                                </a>
                            </div>
                        </div>
                        <!--end::Menu-->
                    </div>
                    <!--end::Aside Menu-->
                </div>
                <!--end::Aside menu-->
                <!--begin::Footer-->
                <div class="aside-footer flex-column-auto pt-5 pb-7 px-5" id="kt_aside_footer">
                    <a href="/metronic8/demo1/../demo1/documentation/getting-started.html" class="btn btn-custom btn-primary w-100" data-bs-toggle="tooltip" data-bs-trigger="hover" data-bs-dismiss-="click" title="" data-bs-original-title="200+ in-house components and 3rd-party plugins">
                        <span class="btn-label">Docs &amp; Components</span>
                        <!--begin::Svg Icon | path: icons/duotune/general/gen005.svg-->
                        <span class="svg-icon btn-icon svg-icon-2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
                                <path opacity="0.3" d="M19 22H5C4.4 22 4 21.6 4 21V3C4 2.4 4.4 2 5 2H14L20 8V21C20 21.6 19.6 22 19 22ZM12.5 18C12.5 17.4 12.6 17.5 12 17.5H8.5C7.9 17.5 8 17.4 8 18C8 18.6 7.9 18.5 8.5 18.5L12 18C12.6 18 12.5 18.6 12.5 18ZM16.5 13C16.5 12.4 16.6 12.5 16 12.5H8.5C7.9 12.5 8 12.4 8 13C8 13.6 7.9 13.5 8.5 13.5H15.5C16.1 13.5 16.5 13.6 16.5 13ZM12.5 8C12.5 7.4 12.6 7.5 12 7.5H8C7.4 7.5 7.5 7.4 7.5 8C7.5 8.6 7.4 8.5 8 8.5H12C12.6 8.5 12.5 8.6 12.5 8Z" fill="currentColor"></path>
                                <rect x="7" y="17" width="6" height="2" rx="1" fill="currentColor"></rect>
                                <rect x="7" y="12" width="10" height="2" rx="1" fill="currentColor"></rect>
                                <rect x="7" y="7" width="6" height="2" rx="1" fill="currentColor"></rect>
                                <path d="M15 8H20L14 2V7C14 7.6 14.4 8 15 8Z" fill="currentColor"></path>
                            </svg>
                        </span>
                        <!--end::Svg Icon-->
                    </a>
                </div>
                <!--end::Footer-->
            </div>
	';
}

function left_menu($menu_array_before, $helppagename = '', $notused = '', $menu_array_after = '', $leftmenuwithoutmainarea = 0, $title = '', $acceptdelayedhtml = 0)
{
	global $user, $conf, $langs, $db, $form;
	global $hookmanager, $menumanager;

	$searchform = '';

	if (!empty($menu_array_before)) {
		dol_syslog("Deprecated parameter menu_array_before was used when calling main::left_menu function. Menu entries of module should now be defined into module descriptor and not provided when calling left_menu.", LOG_WARNING);
	}

	if (empty($conf->dol_hide_leftmenu) && (!defined('NOREQUIREMENU') || !constant('NOREQUIREMENU'))) {
		// Instantiate hooks for external modules
		$hookmanager->initHooks(array('searchform', 'leftblock'));

		print "\n".'<!-- Begin side-nav id-left -->'."\n".'<div class="side-nav"><div id="id-left">'."\n";

		if ($conf->browser->layout == 'phone') {
			$conf->global->MAIN_USE_OLD_SEARCH_FORM = 1; // Select into select2 is awfull on smartphone. TODO Is this still true with select2 v4 ?
		}

		print "\n";

		if (!is_object($form)) {
			$form = new Form($db);
		}
		$selected = -1;
		if (empty($conf->global->MAIN_USE_TOP_MENU_SEARCH_DROPDOWN)) {
			$usedbyinclude = 1;
			$arrayresult = null;
			include DOL_DOCUMENT_ROOT.'/core/ajax/selectsearchbox.php'; // This set $arrayresult

			if ($conf->use_javascript_ajax && empty($conf->global->MAIN_USE_OLD_SEARCH_FORM)) {
				$searchform .= $form->selectArrayFilter('searchselectcombo', $arrayresult, $selected, '', 1, 0, (empty($conf->global->MAIN_SEARCHBOX_CONTENT_LOADED_BEFORE_KEY) ? 1 : 0), 'vmenusearchselectcombo', 1, $langs->trans("Search"), 1);
			} else {
				if (is_array($arrayresult)) {
					foreach ($arrayresult as $key => $val) {
						$searchform .= printSearchForm($val['url'], $val['url'], $val['label'], 'maxwidth125', 'sall', $val['shortcut'], 'searchleft'.$key, $val['img']);
					}
				}
			}

			// Execute hook printSearchForm
			$parameters = array('searchform' => $searchform);
			$reshook = $hookmanager->executeHooks('printSearchForm', $parameters); // Note that $action and $object may have been modified by some hooks
			if (empty($reshook)) {
				$searchform .= $hookmanager->resPrint;
			} else {
				$searchform = $hookmanager->resPrint;
			}

			// Force special value for $searchform
			if (!empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER) || empty($conf->use_javascript_ajax)) {
				$urltosearch = DOL_URL_ROOT.'/core/search_page.php?showtitlebefore=1';
				$searchform = '<div class="blockvmenuimpair blockvmenusearchphone"><div id="divsearchforms1"><a href="'.$urltosearch.'" accesskey="s" alt="'.dol_escape_htmltag($langs->trans("ShowSearchFields")).'">'.$langs->trans("Search").'...</a></div></div>';
			} elseif ($conf->use_javascript_ajax && !empty($conf->global->MAIN_USE_OLD_SEARCH_FORM)) {
				$searchform = '<div class="blockvmenuimpair blockvmenusearchphone"><div id="divsearchforms1"><a href="#" alt="'.dol_escape_htmltag($langs->trans("ShowSearchFields")).'">'.$langs->trans("Search").'...</a></div><div id="divsearchforms2" style="display: none">'.$searchform.'</div>';
				$searchform .= '<script>
            	jQuery(document).ready(function () {
            		jQuery("#divsearchforms1").click(function(){
	                   jQuery("#divsearchforms2").toggle();
	               });
            	});
                </script>' . "\n";
				$searchform .= '</div>';
			}
		}

		// Left column
		print '<!-- Begin left menu -->'."\n";

		print '<div class="vmenu"'.(empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER) ? '' : ' title="Left menu"').'>'."\n\n";

		// Show left menu with other forms
		$menumanager->menu_array = $menu_array_before;
		$menumanager->menu_array_after = $menu_array_after;
		$menumanager->showmenu('left', array('searchform'=>$searchform)); // output menu_array and menu found in database

		// Dolibarr version + help + bug report link
		print "\n";
		print "<!-- Begin Help Block-->\n";
		print '<div id="blockvmenuhelp" class="blockvmenuhelp">'."\n";

		// Version
		if (!empty($conf->global->MAIN_SHOW_VERSION)) {    // Version is already on help picto and on login page.
			$doliurl = 'https://www.dolibarr.org';
			//local communities
			if (preg_match('/fr/i', $langs->defaultlang)) {
				$doliurl = 'https://www.dolibarr.fr';
			}
			if (preg_match('/es/i', $langs->defaultlang)) {
				$doliurl = 'https://www.dolibarr.es';
			}
			if (preg_match('/de/i', $langs->defaultlang)) {
				$doliurl = 'https://www.dolibarr.de';
			}
			if (preg_match('/it/i', $langs->defaultlang)) {
				$doliurl = 'https://www.dolibarr.it';
			}
			if (preg_match('/gr/i', $langs->defaultlang)) {
				$doliurl = 'https://www.dolibarr.gr';
			}

			$appli = constant('DOL_APPLICATION_TITLE');
			if (!empty($conf->global->MAIN_APPLICATION_TITLE)) {
				$appli = $conf->global->MAIN_APPLICATION_TITLE; $doliurl = '';
				if (preg_match('/\d\.\d/', $appli)) {
					if (!preg_match('/'.preg_quote(DOL_VERSION).'/', $appli)) {
						$appli .= " (".DOL_VERSION.")"; // If new title contains a version that is different than core
					}
				} else {
					$appli .= " ".DOL_VERSION;
				}
			} else {
				$appli .= " ".DOL_VERSION;
			}
			print '<div id="blockvmenuhelpapp" class="blockvmenuhelp">';
			if ($doliurl) {
				print '<a class="help" target="_blank" rel="noopener noreferrer" href="'.$doliurl.'">';
			} else {
				print '<span class="help">';
			}
			print $appli;
			if ($doliurl) {
				print '</a>';
			} else {
				print '</span>';
			}
			print '</div>'."\n";
		}

		// Link to bugtrack
		if (!empty($conf->global->MAIN_BUGTRACK_ENABLELINK)) {
			require_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';

			if ($conf->global->MAIN_BUGTRACK_ENABLELINK == 'github') {
				$bugbaseurl = 'https://github.com/Dolibarr/dolibarr/issues/new?labels=Bug';
				$bugbaseurl .= '&title=';
				$bugbaseurl .= urlencode("Bug: ");
				$bugbaseurl .= '&body=';
				$bugbaseurl .= urlencode("# Instructions\n");
				$bugbaseurl .= urlencode("*This is a template to help you report good issues. You may use [Github Markdown](https://help.github.com/articles/getting-started-with-writing-and-formatting-on-github/) syntax to format your issue report.*\n");
				$bugbaseurl .= urlencode("*Please:*\n");
				$bugbaseurl .= urlencode("- *replace the bracket enclosed texts with meaningful information*\n");
				$bugbaseurl .= urlencode("- *remove any unused sub-section*\n");
				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("# Bug\n");
				$bugbaseurl .= urlencode("[*Short description*]\n");
				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("## Environment\n");
				$bugbaseurl .= urlencode("- **Version**: ".DOL_VERSION."\n");
				$bugbaseurl .= urlencode("- **OS**: ".php_uname('s')."\n");
				$bugbaseurl .= urlencode("- **Web server**: ".$_SERVER["SERVER_SOFTWARE"]."\n");
				$bugbaseurl .= urlencode("- **PHP**: ".php_sapi_name().' '.phpversion()."\n");
				$bugbaseurl .= urlencode("- **Database**: ".$db::LABEL.' '.$db->getVersion()."\n");
				$bugbaseurl .= urlencode("- **URL(s)**: ".$_SERVER["REQUEST_URI"]."\n");
				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("## Expected and actual behavior\n");
				$bugbaseurl .= urlencode("[*Verbose description*]\n");
				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("## Steps to reproduce the behavior\n");
				$bugbaseurl .= urlencode("[*Verbose description*]\n");
				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("## [Attached files](https://help.github.com/articles/issue-attachments) (Screenshots, screencasts, dolibarr.log, debugging informations…)\n");
				$bugbaseurl .= urlencode("[*Files*]\n");
				$bugbaseurl .= urlencode("\n");

				$bugbaseurl .= urlencode("\n");
				$bugbaseurl .= urlencode("## Report\n");
			} elseif (!empty($conf->global->MAIN_BUGTRACK_ENABLELINK)) {
				$bugbaseurl = $conf->global->MAIN_BUGTRACK_ENABLELINK;
			} else {
				$bugbaseurl = "";
			}

			// Execute hook printBugtrackInfo
			$parameters = array('bugbaseurl' => $bugbaseurl);
			$reshook = $hookmanager->executeHooks('printBugtrackInfo', $parameters); // Note that $action and $object may have been modified by some hooks
			if (empty($reshook)) {
				$bugbaseurl .= $hookmanager->resPrint;
			} else {
				$bugbaseurl = $hookmanager->resPrint;
			}

			print '<div id="blockvmenuhelpbugreport" class="blockvmenuhelp">';
			print '<a class="help" target="_blank" rel="noopener noreferrer" href="'.$bugbaseurl.'">'.$langs->trans("FindBug").'</a>';
			print '</div>';
		}

		print "</div>\n";
		print "<!-- End Help Block-->\n";
		print "\n";

		print "</div>\n";
		print "<!-- End left menu -->\n";
		print "\n";

		// Execute hook printLeftBlock
		$parameters = array();
		$reshook = $hookmanager->executeHooks('printLeftBlock', $parameters); // Note that $action and $object may have been modified by some hooks
		print $hookmanager->resPrint;

		print '</div></div> <!-- End side-nav id-left -->'; // End div id="side-nav" div id="id-left"
	}

	print "\n";
	print '<!-- Begin right area -->'."\n";

	if (empty($leftmenuwithoutmainarea)) {
		main_area($title);
	}
}


/**
 *  Begin main area
 *
 *  @param	string	$title		Title
 *  @return	void
 */
function main_area($title = '')
{
	global $conf, $langs, $hookmanager;

	if (empty($conf->dol_hide_leftmenu)) {
		print '<div id="id-right">';
	}

	print "\n";

	print '<!-- Begin div class="fiche" -->'."\n".'<div class="fiche">'."\n";

	$hookmanager->initHooks(array('main'));
	$parameters = array();
	$reshook = $hookmanager->executeHooks('printMainArea', $parameters); // Note that $action and $object may have been modified by some hooks
	print $hookmanager->resPrint;

	if (!empty($conf->global->MAIN_ONLY_LOGIN_ALLOWED)) {
		print info_admin($langs->trans("WarningYouAreInMaintenanceMode", $conf->global->MAIN_ONLY_LOGIN_ALLOWED), 0, 0, 1, 'warning maintenancemode');
	}

	// Permit to add user company information on each printed document by setting SHOW_SOCINFO_ON_PRINT
	if (!empty($conf->global->SHOW_SOCINFO_ON_PRINT) && GETPOST('optioncss', 'aZ09') == 'print' && empty(GETPOST('disable_show_socinfo_on_print', 'az09'))) {
		$parameters = array();
		$reshook = $hookmanager->executeHooks('showSocinfoOnPrint', $parameters);
		if (empty($reshook)) {
			print '<!-- Begin show mysoc info header -->'."\n";
			print '<div id="mysoc-info-header">'."\n";
			print '<table class="centpercent div-table-responsive">'."\n";
			print '<tbody>';
			print '<tr><td rowspan="0" class="width20p">';
			if ($conf->global->MAIN_SHOW_LOGO && empty($conf->global->MAIN_OPTIMIZEFORTEXTBROWSER) && !empty($conf->global->MAIN_INFO_SOCIETE_LOGO)) {
				print '<img id="mysoc-info-header-logo" style="max-width:100%" alt="" src="'.DOL_URL_ROOT.'/viewimage.php?cache=1&amp;modulepart=mycompany&amp;file='.urlencode('logos/'.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_LOGO)).'">';
			}
			print '</td><td  rowspan="0" class="width50p"></td></tr>'."\n";
			print '<tr><td class="titre bold">'.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_NOM).'</td></tr>'."\n";
			print '<tr><td>'.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_ADDRESS).'<br>'.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_ZIP).' '.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_TOWN).'</td></tr>'."\n";
			if (!empty($conf->global->MAIN_INFO_SOCIETE_TEL)) {
				print '<tr><td style="padding-left: 1em" class="small">'.$langs->trans("Phone").' : '.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_TEL).'</td></tr>';
			}
			if (!empty($conf->global->MAIN_INFO_SOCIETE_MAIL)) {
				print '<tr><td style="padding-left: 1em" class="small">'.$langs->trans("Email").' : '.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_MAIL).'</td></tr>';
			}
			if (!empty($conf->global->MAIN_INFO_SOCIETE_WEB)) {
				print '<tr><td style="padding-left: 1em" class="small">'.$langs->trans("Web").' : '.dol_escape_htmltag($conf->global->MAIN_INFO_SOCIETE_WEB).'</td></tr>';
			}
			print '</tbody>';
			print '</table>'."\n";
			print '</div>'."\n";
			print '<!-- End show mysoc info header -->'."\n";
		}
	}
}


/**
 *  Return helpbaseurl, helppage and mode
 *
 *  @param	string		$helppagename		Page name ('EN:xxx,ES:eee,FR:fff...' or 'http://localpage')
 *  @param  Translate	$langs				Language
 *  @return	array		Array of help urls
 */
function getHelpParamFor($helppagename, $langs)
{
	$helpbaseurl = '';
	$helppage = '';
	$mode = '';

	if (preg_match('/^http/i', $helppagename)) {
		// If complete URL
		$helpbaseurl = '%s';
		$helppage = $helppagename;
		$mode = 'local';
	} else {
		// If WIKI URL
		$reg = array();
		if (preg_match('/^es/i', $langs->defaultlang)) {
			$helpbaseurl = 'http://wiki.dolibarr.org/index.php/%s';
			if (preg_match('/ES:([^|]+)/i', $helppagename, $reg)) {
				$helppage = $reg[1];
			}
		}
		if (preg_match('/^fr/i', $langs->defaultlang)) {
			$helpbaseurl = 'http://wiki.dolibarr.org/index.php/%s';
			if (preg_match('/FR:([^|]+)/i', $helppagename, $reg)) {
				$helppage = $reg[1];
			}
		}
		if (empty($helppage)) {	// If help page not already found
			$helpbaseurl = 'http://wiki.dolibarr.org/index.php/%s';
			if (preg_match('/EN:([^|]+)/i', $helppagename, $reg)) {
				$helppage = $reg[1];
			}
		}
		$mode = 'wiki';
	}
	return array('helpbaseurl'=>$helpbaseurl, 'helppage'=>$helppage, 'mode'=>$mode);
}


/**
 *  Show a search area.
 *  Used when the javascript quick search is not used.
 *
 *  @param  string	$urlaction          Url post
 *  @param  string	$urlobject          Url of the link under the search box
 *  @param  string	$title              Title search area
 *  @param  string	$htmlmorecss        Add more css
 *  @param  string	$htmlinputname      Field Name input form
 *  @param	string	$accesskey			Accesskey
 *  @param  string  $prefhtmlinputname  Complement for id to avoid multiple same id in the page
 *  @param	string	$img				Image to use
 *  @param	string	$showtitlebefore	Show title before input text instead of into placeholder. This can be set when output is dedicated for text browsers.
 *  @param	string	$autofocus			Set autofocus on field
 *  @return	string
 */
function printSearchForm($urlaction, $urlobject, $title, $htmlmorecss, $htmlinputname, $accesskey = '', $prefhtmlinputname = '', $img = '', $showtitlebefore = 0, $autofocus = 0)
{
	global $conf, $langs, $user;

	$ret = '';
	$ret .= '<form action="'.$urlaction.'" method="post" class="searchform nowraponall tagtr">';
	$ret .= '<input type="hidden" name="token" value="'.newToken().'">';
	$ret .= '<input type="hidden" name="mode" value="search">';
	$ret .= '<input type="hidden" name="savelogin" value="'.dol_escape_htmltag($user->login).'">';
	if ($showtitlebefore) {
		$ret .= '<div class="tagtd left">'.$title.'</div> ';
	}
	$ret .= '<div class="tagtd">';
	$ret .= img_picto('', $img, '', false, 0, 0, '', 'paddingright width20');
	$ret .= '<input type="text" class="flat '.$htmlmorecss.'"';
	$ret .= ' style="background-repeat: no-repeat; background-position: 3px;"';
	$ret .= ($accesskey ? ' accesskey="'.$accesskey.'"' : '');
	$ret .= ' placeholder="'.strip_tags($title).'"';
	$ret .= ($autofocus ? ' autofocus' : '');
	$ret .= ' name="'.$htmlinputname.'" id="'.$prefhtmlinputname.$htmlinputname.'" />';
	$ret .= '<button type="submit" class="button bordertransp" style="padding-top: 4px; padding-bottom: 4px; padding-left: 6px; padding-right: 6px">';
	$ret .= '<span class="fa fa-search"></span>';
	$ret .= '</button>';
	$ret .= '</div>';
	$ret .= "</form>\n";
	return $ret;
}


if (!function_exists("llxFooter")) {
	/**
	 * Show HTML footer
	 * Close div /DIV class=fiche + /DIV id-right + /DIV id-container + /BODY + /HTML.
	 * If global var $delayedhtmlcontent was filled, we output it just before closing the body.
	 *
	 * @param	string	$comment    				A text to add as HTML comment into HTML generated page
	 * @param	string	$zone						'private' (for private pages) or 'public' (for public pages)
	 * @param	int		$disabledoutputofmessages	Clear all messages stored into session without diplaying them
	 * @return	void
	 */
	function llxFooter($comment = '', $zone = 'private', $disabledoutputofmessages = 0)
	{
		global $conf, $db, $langs, $user, $mysoc, $object, $hookmanager;
		global $delayedhtmlcontent;
		global $contextpage, $page, $limit;
		global $dolibarr_distrib;

		$ext = 'layout='.$conf->browser->layout.'&version='.urlencode(DOL_VERSION);

		// Global html output events ($mesgs, $errors, $warnings)
		dol_htmloutput_events($disabledoutputofmessages);

		// Code for search criteria persistence.
		// $user->lastsearch_values was set by the GETPOST when form field search_xxx exists
		if (is_object($user) && !empty($user->lastsearch_values_tmp) && is_array($user->lastsearch_values_tmp)) {
			// Clean and save data
			foreach ($user->lastsearch_values_tmp as $key => $val) {
				unset($_SESSION['lastsearch_values_tmp_'.$key]); // Clean array to rebuild it just after
				if (count($val) && empty($_POST['button_removefilter'])) {	// If there is search criteria to save and we did not click on 'Clear filter' button
					if (empty($val['sortfield'])) {
						unset($val['sortfield']);
					}
					if (empty($val['sortorder'])) {
						unset($val['sortorder']);
					}
					dol_syslog('Save lastsearch_values_tmp_'.$key.'='.json_encode($val, 0)." (systematic recording of last search criterias)");
					$_SESSION['lastsearch_values_tmp_'.$key] = json_encode($val);
					unset($_SESSION['lastsearch_values_'.$key]);
				}
			}
		}


		$relativepathstring = $_SERVER["PHP_SELF"];
		// Clean $relativepathstring
		if (constant('DOL_URL_ROOT')) {
			$relativepathstring = preg_replace('/^'.preg_quote(constant('DOL_URL_ROOT'), '/').'/', '', $relativepathstring);
		}
		$relativepathstring = preg_replace('/^\//', '', $relativepathstring);
		$relativepathstring = preg_replace('/^custom\//', '', $relativepathstring);
		if (preg_match('/list\.php$/', $relativepathstring)) {
			unset($_SESSION['lastsearch_contextpage_tmp_'.$relativepathstring]);
			unset($_SESSION['lastsearch_page_tmp_'.$relativepathstring]);
			unset($_SESSION['lastsearch_limit_tmp_'.$relativepathstring]);

			if (!empty($contextpage)) {
				$_SESSION['lastsearch_contextpage_tmp_'.$relativepathstring] = $contextpage;
			}
			if (!empty($page) && $page > 0) {
				$_SESSION['lastsearch_page_tmp_'.$relativepathstring] = $page;
			}
			if (!empty($limit) && $limit != $conf->liste_limit) {
				$_SESSION['lastsearch_limit_tmp_'.$relativepathstring] = $limit;
			}

			unset($_SESSION['lastsearch_contextpage_'.$relativepathstring]);
			unset($_SESSION['lastsearch_page_'.$relativepathstring]);
			unset($_SESSION['lastsearch_limit_'.$relativepathstring]);
		}

		// Core error message
		if (!empty($conf->global->MAIN_CORE_ERROR)) {
			// Ajax version
			if ($conf->use_javascript_ajax) {
				$title = img_warning().' '.$langs->trans('CoreErrorTitle');
				print ajax_dialog($title, $langs->trans('CoreErrorMessage'));
			} else {
				// html version
				$msg = img_warning().' '.$langs->trans('CoreErrorMessage');
				print '<div class="error">'.$msg.'</div>';
			}

			//define("MAIN_CORE_ERROR",0);      // Constant was defined and we can't change value of a constant
		}

		print "\n\n";

		print '</div> <!-- End div class="fiche" -->'."\n"; // End div fiche

		if (empty($conf->dol_hide_leftmenu)) {
			print '</div> <!-- End div id-right -->'."\n"; // End div id-right
		}

		if (empty($conf->dol_hide_leftmenu) && empty($conf->dol_use_jmobile)) {
			print '</div> <!-- End div id-container -->'."\n"; // End div container
		}

		print "\n";
		if ($comment) {
			print '<!-- '.$comment.' -->'."\n";
		}

		printCommonFooter($zone);

		if (!empty($delayedhtmlcontent)) {
			print $delayedhtmlcontent;
		}

		if (!empty($conf->use_javascript_ajax)) {
			print "\n".'<!-- Includes JS Footer of Dolibarr -->'."\n";
			print '<script src="'.DOL_URL_ROOT.'/core/js/lib_foot.js.php?lang='.$langs->defaultlang.($ext ? '&'.$ext : '').'"></script>'."\n";
		}

		// Wrapper to add log when clicking on download or preview
		if (!empty($conf->blockedlog->enabled) && is_object($object) && !empty($object->id) && $object->id > 0 && $object->statut > 0) {
			if (in_array($object->element, array('facture'))) {       // Restrict for the moment to element 'facture'
				print "\n<!-- JS CODE TO ENABLE log when making a download or a preview of a document -->\n";
				?>
				<script>
				jQuery(document).ready(function () {
					$('a.documentpreview').click(function() {
						$.post('<?php echo DOL_URL_ROOT."/blockedlog/ajax/block-add.php" ?>'
								, {
									id:<?php echo $object->id; ?>
									, element:'<?php echo $object->element ?>'
									, action:'DOC_PREVIEW'
									, token: '<?php echo currentToken(); ?>'
								}
						);
					});
					$('a.documentdownload').click(function() {
						$.post('<?php echo DOL_URL_ROOT."/blockedlog/ajax/block-add.php" ?>'
								, {
									id:<?php echo $object->id; ?>
									, element:'<?php echo $object->element ?>'
									, action:'DOC_DOWNLOAD'
									, token: '<?php echo currentToken(); ?>'
								}
						);
					});
				});
				</script>
				<?php
			}
		}

		// A div for the address popup
		print "\n<!-- A div to allow dialog popup by jQuery('#dialogforpopup').dialog() -->\n";
		print '<div id="dialogforpopup" style="display: none;"></div>'."\n";

		// Add code for the asynchronous anonymous first ping (for telemetry)
		// You can use &forceping=1 in parameters to force the ping if the ping was already sent.
		$forceping = GETPOST('forceping', 'alpha');
		if (($_SERVER["PHP_SELF"] == DOL_URL_ROOT.'/index.php') || $forceping) {
			//print '<!-- instance_unique_id='.$conf->file->instance_unique_id.' MAIN_FIRST_PING_OK_ID='.$conf->global->MAIN_FIRST_PING_OK_ID.' -->';
			$hash_unique_id = md5('dolibarr'.$conf->file->instance_unique_id);

			if (empty($conf->global->MAIN_FIRST_PING_OK_DATE)
				|| (!empty($conf->file->instance_unique_id) && ($hash_unique_id != $conf->global->MAIN_FIRST_PING_OK_ID) && ($conf->global->MAIN_FIRST_PING_OK_ID != 'disabled'))
			|| $forceping) {
				// No ping done if we are into an alpha version
				if (strpos('alpha', DOL_VERSION) > 0 && !$forceping) {
					print "\n<!-- NO JS CODE TO ENABLE the anonymous Ping. It is an alpha version -->\n";
				} elseif (empty($_COOKIE['DOLINSTALLNOPING_'.$hash_unique_id]) || $forceping) {	// Cookie is set when we uncheck the checkbox in the installation wizard.
					// MAIN_LAST_PING_KO_DATE
					// Disable ping if MAIN_LAST_PING_KO_DATE is set and is recent (this month)
					if (!empty($conf->global->MAIN_LAST_PING_KO_DATE) && substr($conf->global->MAIN_LAST_PING_KO_DATE, 0, 6) == dol_print_date(dol_now(), '%Y%m') && !$forceping) {
						print "\n<!-- NO JS CODE TO ENABLE the anonymous Ping. An error already occured this month, we will try later. -->\n";
					} else {
						include_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';

						print "\n".'<!-- Includes JS for Ping of Dolibarr forceping='.$forceping.' MAIN_FIRST_PING_OK_DATE='.getDolGlobalString("MAIN_FIRST_PING_OK_DATE").' MAIN_FIRST_PING_OK_ID='.getDolGlobalString("MAIN_FIRST_PING_OK_ID").' MAIN_LAST_PING_KO_DATE='.getDolGlobalString("MAIN_LAST_PING_KO_DATE").' -->'."\n";
						print "\n<!-- JS CODE TO ENABLE the anonymous Ping -->\n";
						$url_for_ping = (empty($conf->global->MAIN_URL_FOR_PING) ? "https://ping.dolibarr.org/" : $conf->global->MAIN_URL_FOR_PING);
						// Try to guess the distrib used
						$distrib = 'standard';
						if ($_SERVER["SERVER_ADMIN"] == 'doliwamp@localhost') {
							$distrib = 'doliwamp';
						}
						if (!empty($dolibarr_distrib)) {
							$distrib = $dolibarr_distrib;
						}
						?>
							<script>
							jQuery(document).ready(function (tmp) {
								console.log("Try Ping with hash_unique_id is md5('dolibarr'+instance_unique_id)");
								$.ajax({
									  method: "POST",
									  url: "<?php echo $url_for_ping ?>",
									  timeout: 500,     // timeout milliseconds
									  cache: false,
									  data: {
										  hash_algo: 'md5',
										  hash_unique_id: '<?php echo dol_escape_js($hash_unique_id); ?>',
										  action: 'dolibarrping',
										  version: '<?php echo (float) DOL_VERSION; ?>',
										  entity: '<?php echo (int) $conf->entity; ?>',
										  dbtype: '<?php echo dol_escape_js($db->type); ?>',
										  country_code: '<?php echo $mysoc->country_code ? dol_escape_js($mysoc->country_code) : 'unknown'; ?>',
										  php_version: '<?php echo dol_escape_js(phpversion()); ?>',
										  os_version: '<?php echo dol_escape_js(version_os('smr')); ?>',
										  distrib: '<?php echo $distrib ? dol_escape_js($distrib) : 'unknown'; ?>',
										  token: 'notrequired'
									  },
									  success: function (data, status, xhr) {   // success callback function (data contains body of response)
											console.log("Ping ok");
											$.ajax({
												method: 'GET',
												url: '<?php echo DOL_URL_ROOT.'/core/ajax/pingresult.php'; ?>',
												timeout: 500,     // timeout milliseconds
												cache: false,
												data: { hash_algo: 'md5', hash_unique_id: '<?php echo dol_escape_js($hash_unique_id); ?>', action: 'firstpingok', token: 'notrequired' },	// for update
											  });
									  },
									  error: function (data,status,xhr) {   // error callback function
											console.log("Ping ko: " + data);
											$.ajax({
												  method: 'GET',
												  url: '<?php echo DOL_URL_ROOT.'/core/ajax/pingresult.php'; ?>',
												  timeout: 500,     // timeout milliseconds
												  cache: false,
												  data: { hash_algo: 'md5', hash_unique_id: '<?php echo dol_escape_js($hash_unique_id); ?>', action: 'firstpingko', token: 'notrequired' },
												});
									  }
								});
							});
							</script>
						<?php
					}
				} else {
					$now = dol_now();
					print "\n<!-- NO JS CODE TO ENABLE the anonymous Ping. It was disabled -->\n";
					include_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
					dolibarr_set_const($db, 'MAIN_FIRST_PING_OK_DATE', dol_print_date($now, 'dayhourlog', 'gmt'), 'chaine', 0, '', $conf->entity);
					dolibarr_set_const($db, 'MAIN_FIRST_PING_OK_ID', 'disabled', 'chaine', 0, '', $conf->entity);
				}
			}
		}

		$reshook = $hookmanager->executeHooks('beforeBodyClose'); // Note that $action and $object may have been modified by some hooks
		if ($reshook > 0) {
			print $hookmanager->resPrint;
		}

		print '   <script src="/metronic8/demo1/assets/plugins/global/plugins.bundle.js"></script>
		<script src="/metronic8/demo1/assets/js/scripts.bundle.js"></script>
		<!--end::Global Javascript Bundle-->
		<!--begin::Page Vendors Javascript(used by this page)-->
		<script src="/metronic8/demo1/assets/plugins/custom/fullcalendar/fullcalendar.bundle.js"></script>
	<script type="text/javascript" id="">!function(b,e,f,g,a,c,d){b.fbq||(a=b.fbq=function(){a.callMethod?a.callMethod.apply(a,arguments):a.queue.push(arguments)},b._fbq||(b._fbq=a),a.push=a,a.loaded=!0,a.version="2.0",a.queue=[],c=e.createElement(f),c.async=!0,c.src=g,d=e.getElementsByTagName(f)[0],d.parentNode.insertBefore(c,d))}(window,document,"script","https://connect.facebook.net/en_US/fbevents.js");fbq("init","738802870177541");fbq("track","PageView");</script>
	<noscript><img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id=738802870177541&amp;ev=PageView&amp;noscript=1"></noscript>
	<script type="text/javascript" id="">try{(function(){var a=google_tag_manager["GTM-5FS8GGP"].macro(6);a="undefined"==typeof a?google_tag_manager["GTM-5FS8GGP"].macro(7):a;var b=new Date;b.setTime(b.getTime()+18E5);var c="gtm-session-start";b=b.toGMTString();var d="/",e=".keenthemes.com";document.cookie=c+"\x3d"+a+"; Expires\x3d"+b+"; domain\x3d"+e+"; Path\x3d"+d})()}catch(a){};</script><script type="text/javascript" id="">(function(){var a=google_tag_manager["GTM-5FS8GGP"].macro(8)-0+1,b=".keenthemes.com";document.cookie="damlPageCount\x3d"+a+";domain\x3d"+b+";path\x3d/;"})();</script>
		<script src="/metronic8/demo1/assets/plugins/custom/datatables/datatables.bundle.js"></script>
		<!--end::Page Vendors Javascript-->
		<!--begin::Page Custom Javascript(used by this page)-->
		<script src="/metronic8/demo1/assets/js/widgets.bundle.js"></script>
		<script src="/metronic8/demo1/assets/js/custom/widgets.js"></script>
		<script src="/metronic8/demo1/assets/js/custom/apps/chat/chat.js"></script>
		<script src="/metronic8/demo1/assets/js/custom/intro.js"></script>
		<script src="/metronic8/demo1/assets/js/custom/utilities/modals/upgrade-plan.js"></script>
		<script src="/metronic8/demo1/assets/js/custom/utilities/modals/create-app.js"></script>
		<script src="/metronic8/demo1/assets/js/custom/utilities/modals/users-search.js"></script>
		<!--end::Page Custom Javascript-->
		<!--end::Javascript-->';

		print "</body>\n";
		print "</html>\n";
	}
}
