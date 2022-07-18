<?php 
    require '../../main.inc.php';
    

    global $db;
    
    llxHeader();
    $facid = GETPOST('facid', 'int');
    print '<br>Productos</br>'; 
  
    $sql='SELECT fact.*';
    $sql.=' FROM '.MAIN_DB_PREFIX.'facturedet as fact';
    $sql.=' WHERE  fk_facture = '.$facid.';';
    //print $sql;
    
	$result = $db->query($sql);
    if ($result) {
        $i = 0;
        $num = $db->num_rows($result);

        while ($i < $num) {
            $objp = $db->fetch_object($result);
            print '<br>'.$objp->rowid.'  '.$objp->description.'  '.round($objp->total_ht).'  '.round($objp->total_tva).'  '.round($objp->total_ttc).'</br>';
            $i++;
        }
    } else {
        dol_print_error($db, '');
    }

    print '<br>Emisor</br>'; 
    print '<br>'.$mysoc->idprof1.'  '.$mysoc->nom.'  '.$mysoc->address.'  '.$mysoc->phone.'  '.$mysoc->email.'  '.$mysoc->url;
    
    print '<br>Cliente</br>'; 

    $sql='SELECT ls.*';
    $sql.=' FROM '.MAIN_DB_PREFIX.'facture lf';
    $sql.=' JOIN '.MAIN_DB_PREFIX.'societe  ls ON ls.rowid =lf.fk_soc' ;
    $sql.=' WHERE  lf.rowid = '.$facid.';';
    $result = $db->query($sql);
    if ($result) {
        $i = 0;
        $num = $db->num_rows($result);

        while ($i < $num) {
            $objp = $db->fetch_object($result);
            print '<br>'.$objp->rowid.'  '.$objp->siren.'  '.$objp->address .'  '.$objp->email.'  '.round($objp->total_ttc).'</br>';
            $i++;
        }
    } else {
        dol_print_error($db, '');
    }
    $headers = array('token: lala', 'inicio: test');
    // probar conexion 
    
    $url='http://servicio-facturacion_nginx_1/api/listartipo';
    $curl=curl_init();
    // curl_setopt_array($curl,array(
    //         CURLOPT_RETURNTRANSFER => 1,
    //         CURLOPT_URL            => $url,
    //         CURLOPT_HTTPHEADER     => $headers,
    //         CURLOPT_USERAGENT      => 'Codular Sample cURL Request'
    // ));
    print $url;
    curl_setopt($curl, CURLOPT_URL, $url); 
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); 
    curl_setopt($curl, CURLOPT_HEADER, 0); 
    $output = curl_exec($curl);
    // print $output;
    $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    print json_encode($output);
    print json_encode($httpcode);
    print curl_error($curl);
    curl_close($curl);
    // generar un pdf con la previsualizacion 

    print '<iframe class="embed-responsive-item" src=\'http://localhost:9000/api/listartipo\'></iframe>'

    


?>