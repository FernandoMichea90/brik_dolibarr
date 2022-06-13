<?php 
    function logger($log){
        
       
        if(!file_exists("/var/www/html/logs/log.txt")){
            file_put_contents('/var/www/html/logs/log.txt','');
        }
        $ip=$_SERVER['REMOTE_ADDR'];
        $time=date('m/d/y h:iA',time());
        $contents=file_get_contents('/var/www/html/logs/log.txt');
        $contents .="$ip\t$time\t$log\r";
        file_put_contents('/var/www/html/logs/log.txt',$contents);
        }
?>