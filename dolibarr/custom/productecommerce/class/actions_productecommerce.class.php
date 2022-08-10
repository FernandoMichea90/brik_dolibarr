<?php
/* Copyright (C) 2022 SuperAdmin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * \file    productecommerce/class/actions_productecommerce.class.php
 * \ingroup productecommerce
 * \brief   Example hook overload.
 *
 * Put detailed description here.
 */
require_once DOL_DOCUMENT_ROOT . '/product/class/product.class.php';
// require_once DOL_DOCUMENT_ROOT . '/custom/productecommerce/class/productecom.class.php';


/**
 * Class ActionsProductEcommerce
 */
class ActionsProductEcommerce
{
	/**
	 * @var DoliDB Database handler.
	 */
	public $db;

	/**
	 * @var string Error code (or message)
	 */
	public $error = '';

	/**
	 * @var array Errors
	 */
	public $errors = array();


	/**
	 * @var array Hook results. Propagated to $hookmanager->resArray for later reuse
	 */
	public $results = array();

	/**
	 * @var string String displayed by executeHook() immediately after return
	 */
	public $resprints;


	/**
	 * Constructor
	 *
	 *  @param		DoliDB		$db      Database handler
	 */
	public function __construct($db)
	{
		$this->db = $db;
	}


	/**
	 * Execute action
	 *
	 * @param	array			$parameters		Array of parameters
	 * @param	CommonObject    $object         The object to process (an invoice if you are in invoice module, a propale in propale's module, etc...)
	 * @param	string			$action      	'add', 'update', 'view'
	 * @return	int         					<0 if KO,
	 *                           				=0 if OK but we want to process standard actions too,
	 *                            				>0 if OK and we want to replace standard actions.
	 */
	public function getNomUrl($parameters, &$object, &$action)
	{
		global $db, $langs, $conf, $user;
		$this->resprints = '';
		return 0;
	}

	/**
	 * Overloading the doActions function : replacing the parent's function with the one below
	 *
	 * @param   array           $parameters     Hook metadatas (context, etc...)
	 * @param   CommonObject    $object         The object to process (an invoice if you are in invoice module, a propale in propale's module, etc...)
	 * @param   string          $action         Current action (if set). Generally create or edit or null
	 * @param   HookManager     $hookmanager    Hook manager propagated to allow calling another hook
	 * @return  int                             < 0 on error, 0 on success, 1 to replace standard code
	 */
	public function doActions($parameters, &$object, &$action, $hookmanager)
	{
		global $conf, $user, $langs;

		$error = 0; // Error counter

		/* print_r($parameters); print_r($object); echo "action: " . $action; */
		if (in_array($parameters['currentcontext'], array('somecontext1', 'somecontext2'))) {	    // do something only for the context 'somecontext1' or 'somecontext2'
			// Do what you want here...
			// You can for example call global vars like $fieldstosearchall to overwrite them, or update database depending on $action and $_POST values.
		}

		if (!$error) {
			$this->results = array('myreturn' => 999);
			$this->resprints = 'A text to show';
			return 0; // or return 1 to replace standard code
		} else {
			$this->errors[] = 'Error message';
			return -1;
		}
	}


	/**
	 * Overloading the doMassActions function : replacing the parent's function with the one below
	 *
	 * @param   array           $parameters     Hook metadatas (context, etc...)
	 * @param   CommonObject    $object         The object to process (an invoice if you are in invoice module, a propale in propale's module, etc...)
	 * @param   string          $action         Current action (if set). Generally create or edit or null
	 * @param   HookManager     $hookmanager    Hook manager propagated to allow calling another hook
	 * @return  int                             < 0 on error, 0 on success, 1 to replace standard code
	 */
	public function doMassActions($parameters, &$object, &$action, $hookmanager)
	{
		global $conf, $user, $langs;

		$error = 0; // Error counter

		/* print_r($parameters); print_r($object); echo "action: " . $action; */
		if (in_array($parameters['currentcontext'], array('somecontext1', 'somecontext2'))) {		// do something only for the context 'somecontext1' or 'somecontext2'
			foreach ($parameters['toselect'] as $objectid) {
				// Do action on each object id
			}
		}

		if (!$error) {
			$this->results = array('myreturn' => 999);
			$this->resprints = 'A text to show';
			return 0; // or return 1 to replace standard code
		} else {
			$this->errors[] = 'Error message';
			return -1;
		}
	}


	/**
	 * Overloading the addMoreMassActions function : replacing the parent's function with the one below
	 *
	 * @param   array           $parameters     Hook metadatas (context, etc...)
	 * @param   CommonObject    $object         The object to process (an invoice if you are in invoice module, a propale in propale's module, etc...)
	 * @param   string          $action         Current action (if set). Generally create or edit or null
	 * @param   HookManager     $hookmanager    Hook manager propagated to allow calling another hook
	 * @return  int                             < 0 on error, 0 on success, 1 to replace standard code
	 */
	public function addMoreMassActions($parameters, &$object, &$action, $hookmanager)
	{
		global $conf, $user, $langs;

		$error = 0; // Error counter
		$disabled = 1;

		/* print_r($parameters); print_r($object); echo "action: " . $action; */
		if (in_array($parameters['currentcontext'], array('somecontext1', 'somecontext2'))) {		// do something only for the context 'somecontext1' or 'somecontext2'
			$this->resprints = '<option value="0"' . ($disabled ? ' disabled="disabled"' : '') . '>' . $langs->trans("ProductEcommerceMassAction") . '</option>';
		}

		if (!$error) {
			return 0; // or return 1 to replace standard code
		} else {
			$this->errors[] = 'Error message';
			return -1;
		}
	}



	/**
	 * Execute action
	 *
	 * @param	array	$parameters     Array of parameters
	 * @param   Object	$object		   	Object output on PDF
	 * @param   string	$action     	'add', 'update', 'view'
	 * @return  int 		        	<0 if KO,
	 *                          		=0 if OK but we want to process standard actions too,
	 *  	                            >0 if OK and we want to replace standard actions.
	 */
	public function beforePDFCreation($parameters, &$object, &$action)
	{
		global $conf, $user, $langs;
		global $hookmanager;

		$outputlangs = $langs;

		$ret = 0;
		$deltemp = array();
		dol_syslog(get_class($this) . '::executeHooks action=' . $action);

		/* print_r($parameters); print_r($object); echo "action: " . $action; */
		if (in_array($parameters['currentcontext'], array('somecontext1', 'somecontext2'))) {		// do something only for the context 'somecontext1' or 'somecontext2'
		}

		return $ret;
	}

	/**
	 * Execute action
	 *
	 * @param	array	$parameters     Array of parameters
	 * @param   Object	$pdfhandler     PDF builder handler
	 * @param   string	$action         'add', 'update', 'view'
	 * @return  int 		            <0 if KO,
	 *                                  =0 if OK but we want to process standard actions too,
	 *                                  >0 if OK and we want to replace standard actions.
	 */
	public function afterPDFCreation($parameters, &$pdfhandler, &$action)
	{
		global $conf, $user, $langs;
		global $hookmanager;

		$outputlangs = $langs;

		$ret = 0;
		$deltemp = array();
		dol_syslog(get_class($this) . '::executeHooks action=' . $action);

		/* print_r($parameters); print_r($object); echo "action: " . $action; */
		if (in_array($parameters['currentcontext'], array('somecontext1', 'somecontext2'))) {
			// do something only for the context 'somecontext1' or 'somecontext2'
		}

		return $ret;
	}



	/**
	 * Overloading the loadDataForCustomReports function : returns data to complete the customreport tool
	 *
	 * @param   array           $parameters     Hook metadatas (context, etc...)
	 * @param   string          $action         Current action (if set). Generally create or edit or null
	 * @param   HookManager     $hookmanager    Hook manager propagated to allow calling another hook
	 * @return  int                             < 0 on error, 0 on success, 1 to replace standard code
	 */
	public function loadDataForCustomReports($parameters, &$action, $hookmanager)
	{
		global $conf, $user, $langs;

		$langs->load("productecommerce@productecommerce");

		$this->results = array();

		$head = array();
		$h = 0;

		if ($parameters['tabfamily'] == 'productecommerce') {
			$head[$h][0] = dol_buildpath('/module/index.php', 1);
			$head[$h][1] = $langs->trans("Home");
			$head[$h][2] = 'home';
			$h++;

			$this->results['title'] = $langs->trans("ProductEcommerce");
			$this->results['picto'] = 'productecommerce@productecommerce';
		}

		$head[$h][0] = 'customreports.php?objecttype=' . $parameters['objecttype'] . (empty($parameters['tabfamily']) ? '' : '&tabfamily=' . $parameters['tabfamily']);
		$head[$h][1] = $langs->trans("CustomReports");
		$head[$h][2] = 'customreports';

		$this->results['head'] = $head;

		return 1;
	}



	/**
	 * Overloading the restrictedArea function : check permission on an object
	 *
	 * @param   array           $parameters     Hook metadatas (context, etc...)
	 * @param   string          $action         Current action (if set). Generally create or edit or null
	 * @param   HookManager     $hookmanager    Hook manager propagated to allow calling another hook
	 * @return  int 		      			  	<0 if KO,
	 *                          				=0 if OK but we want to process standard actions too,
	 *  	                            		>0 if OK and we want to replace standard actions.
	 */
	public function restrictedArea($parameters, &$action, $hookmanager)
	{
		global $user;

		if ($parameters['features'] == 'myobject') {
			if ($user->rights->productecommerce->myobject->read) {
				$this->results['result'] = 1;
				return 1;
			} else {
				$this->results['result'] = 0;
				return 1;
			}
		}

		return 0;
	}

	/**
	 * Execute action completeTabsHead
	 *
	 * @param   array           $parameters     Array of parameters
	 * @param   CommonObject    $object         The object to process (an invoice if you are in invoice module, a propale in propale's module, etc...)
	 * @param   string          $action         'add', 'update', 'view'
	 * @param   Hookmanager     $hookmanager    hookmanager
	 * @return  int                             <0 if KO,
	 *                                          =0 if OK but we want to process standard actions too,
	 *                                          >0 if OK and we want to replace standard actions.
	 */
	public function completeTabsHead(&$parameters, &$object, &$action, $hookmanager)
	{
		global $langs, $conf, $user;

		if (!isset($parameters['object']->element)) {
			return 0;
		}
		if ($parameters['mode'] == 'remove') {
			// utilisé si on veut faire disparaitre des onglets.
			return 0;
		} elseif ($parameters['mode'] == 'add') {
			$langs->load('productecommerce@productecommerce');
			// utilisé si on veut ajouter des onglets.
			$counter = count($parameters['head']);
			$element = $parameters['object']->element;
			$id = $parameters['object']->id;
			// verifier le type d'onglet comme member_stats où ça ne doit pas apparaitre
			// if (in_array($element, ['societe', 'member', 'contrat', 'fichinter', 'project', 'propal', 'commande', 'facture', 'order_supplier', 'invoice_supplier'])) {
			if (in_array($element, ['context1', 'context2'])) {
				$datacount = 0;

				$parameters['head'][$counter][0] = dol_buildpath('/productecommerce/productecommerce_tab.php', 1) . '?id=' . $id . '&amp;module=' . $element;
				$parameters['head'][$counter][1] = $langs->trans('ProductEcommerceTab');
				if ($datacount > 0) {
					$parameters['head'][$counter][1] .= '<span class="badge marginleftonlyshort">' . $datacount . '</span>';
				}
				$parameters['head'][$counter][2] = 'productecommerceemails';
				$counter++;
			}
			if ($counter > 0 && (int) DOL_VERSION < 14) {
				$this->results = $parameters['head'];
				// return 1 to replace standard code
				return 1;
			} else {
				// en V14 et + $parameters['head'] est modifiable par référence
				return 0;
			}
		}
	}

	/* Add here any other hooked methods... */
	public function mostrarProductos($parameters, &$object, &$action, $hookmanager)
	{
		global $conf, $user, $langs, $db;

		$error = 0; // Error counter
		$disabled = 1;
		$product_static = new Product($db);
		// $product_test = new ProductEcom($db);

		$type = '';
		/* print_r($parameters); print_r($object); echo "action: " . $action; */
		if (in_array($parameters['currentcontext'], array('productecommerce', 'somecontext2'))) {		// do something only for the context 'somecontext1' or 'somecontext2'

			// if ((!empty($conf->product->enabled) || !empty($conf->service->enabled)) && ($user->rights->produit->lire || $user->rights->service->lire)) {
			$max = 15;
			$sql = "SELECT p.rowid, p.label, p.price, p.ref, p.fk_product_type, p.tosell, p.tobuy, p.tobatch, p.fk_price_expression,";
			$sql .= " p.entity,";
			$sql .= " p.tms as datem";
			$sql .= " FROM " . MAIN_DB_PREFIX . "product as p";
			$sql .= " WHERE p.entity IN (" . getEntity($product_static->element, 1) . ")";
			if ($type != '') {
				$sql .= " AND p.fk_product_type = " . ((int) $type);
			}
			// Add where from hooks
			$parameters = array();
			$reshook = $hookmanager->executeHooks('printFieldListWhere', $parameters); // Note that $action and $object may have been modified by hook
			$sql .= $hookmanager->resPrint;
			$sql .= $db->order("p.tms", "DESC");
			$sql .= $db->plimit($max, 0);

			//print $sql;
			$result = $db->query($sql);
			if ($result) {
				$num = $db->num_rows($result);

				$i = 0;

				if ($num > 0) {
					$transRecordedType = $langs->trans("LastModifiedProductsAndServices", $max);
					if (isset($_GET["type"]) && $_GET["type"] == 0) {
						$transRecordedType = $langs->trans("LastRecordedProducts", $max);
					}
					if (isset($_GET["type"]) && $_GET["type"] == 1) {
						$transRecordedType = $langs->trans("LastRecordedServices", $max);
					}

					print '<div class="div-table-responsive-no-min">';
					print '<table class="noborder centpercent">';

					$colnb = 2;
					if (empty($conf->global->PRODUIT_MULTIPRICES)) {
						$colnb++;
					}

					print '<tr class="liste_titre"><th colspan="' . $colnb . '">' . $transRecordedType . '</th>';
					print '<th class="right" colspan="3"><a href="' . DOL_URL_ROOT . '/product/list.php?sortfield=p.tms&sortorder=DESC">' . $langs->trans("FullList") . '</td>';
					print '<th>Estado</th>';
					print '</tr>';

					while ($i < $num) {
						$this->existeProducto();
						$objp = $db->fetch_object($result);

						$product_static->id = $objp->rowid;
						$product_static->ref = $objp->ref;
						$product_static->label = $objp->label;
						$product_static->type = $objp->fk_product_type;
						$product_static->entity = $objp->entity;
						$product_static->status = $objp->tosell;
						$product_static->status_buy = $objp->tobuy;
						$product_static->status_batch = $objp->tobatch;

						// Multilangs
						if (!empty($conf->global->MAIN_MULTILANGS)) {
							$sql = "SELECT label";
							$sql .= " FROM " . MAIN_DB_PREFIX . "product_lang";
							$sql .= " WHERE fk_product = " . ((int) $objp->rowid);
							$sql .= " AND lang = '" . $db->escape($langs->getDefaultLang()) . "'";

							$resultd = $db->query($sql);
							if ($resultd) {
								$objtp = $db->fetch_object($resultd);
								if ($objtp && $objtp->label != '') {
									$objp->label = $objtp->label;
								}
							}
						}


						print '<tr class="oddeven">';
						print '<td class="nowraponall tdoverflowmax100">';
						print $product_static->getNomUrl(1, '', 16);
						print "</td>\n";
						print '<td class="tdoverflowmax200" title="' . dol_escape_htmltag($objp->label) . '">' . dol_escape_htmltag($objp->label) . '</td>';
						print "<td>";
						print dol_print_date($db->jdate($objp->datem), 'day');
						print "</td>";
						// Sell price
						if (empty($conf->global->PRODUIT_MULTIPRICES)) {
							if (!empty($conf->dynamicprices->enabled) && !empty($objp->fk_price_expression)) {
								$product = new Product($db);
								$product->fetch($objp->rowid);
								$priceparser = new PriceParser($db);
								$price_result = $priceparser->parseProduct($product);
								if ($price_result >= 0) {
									$objp->price = $price_result;
								}
							}
							print '<td class="nowraponall amount right">';
							if (isset($objp->price_base_type) && $objp->price_base_type == 'TTC') {
								print price($objp->price_ttc) . ' ' . $langs->trans("TTC");
							} else {
								print price($objp->price) . ' ' . $langs->trans("HT");
							}
							print '</td>';
						}
						print '<td class="right nowrap width25"><span class="statusrefsell">';
						print $product_static->LibStatut($objp->tosell, 3, 0);
						print "</span></td>";
						print '<td class="right nowrap width25"><span class="statusrefbuy">';
						print $product_static->LibStatut($objp->tobuy, 3, 1);
						print "</span></td>";
						print '<td class="right nowrap width25">';
						$caja_estado = '<div class="valignmiddle inline-block marginleftonly marginrightonly">';
						$caja_estado .= '<a class="reposition valignmiddle" href="'.$_SERVER["PHP_SELF"].'?product='.$product_static->id.'&estado=active">';
						$caja_estado .= img_picto($langs->trans("Activated"), 'switch_off');
						$caja_estado .= '</a> </div>';
						print $caja_estado;
						print "</td>";
						print "</tr>\n";
						$i++;
					}

					$db->free($result);

					print "</table>";
					print '</div>';
					print '<br>';
				}
			} else {
				dol_print_error($db);
			}
			// }
		}

		if (!$error) {
			return 0; // or return 1 to replace standard code
		} else {
			$this->errors[] = 'Error message';
			return -1;
		}
	}

	// ver si existe el producto en ecommerce 
	public function existeProducto() {
			print 'existe el producto';
		}
}

