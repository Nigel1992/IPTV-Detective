<?php
session_start();
header('Content-Type: text/html; charset=UTF-8');

$db = new mysqli('sql209.infinityfree.com:3306', 'if0_36724021', 'mebOwvAPbUMmFPs', 'if0_36724021_iptv');
if ($db->connect_error) die("DB Error");

if (isset($_GET['logout'])) { session_destroy(); header('Location: '.$_SERVER['PHP_SELF']); exit; }

$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $u = $_POST['username'] ?? '';
    $p = hash('sha256', $_POST['password'] ?? '');
    $stmt = $db->prepare("SELECT id, username, role FROM admin_users WHERE username=? AND password_hash=?");
    $stmt->bind_param("ss", $u, $p);
    $stmt->execute();
    $r = $stmt->get_result();
    if ($row = $r->fetch_assoc()) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_user'] = $row['username'];
        $_SESSION['admin_id'] = $row['id'];
        $_SESSION['admin_role'] = $row['role'];
        $db->query("UPDATE admin_users SET last_login=NOW() WHERE id=".$row['id']);
    } else { $login_error = 'Invalid credentials'; }
}

if (!isset($_SESSION['admin_logged_in']) || !$_SESSION['admin_logged_in']) { ?>
<!DOCTYPE html><html><head><title>Login</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='grad' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' style='stop-color:%23dc3545;stop-opacity:1' /%3E%3Cstop offset='100%25' style='stop-color:%23c82333;stop-opacity:1' /%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M50 10 L75 25 L75 50 C75 75 50 90 50 90 C50 90 25 75 25 50 L25 25 Z' fill='url(%23grad)' stroke='white' stroke-width='2'/%3E%3Ccircle cx='50' cy='50' r='12' fill='white'/%3E%3Cpath d='M50 45 L50 55 M45 50 L55 50' stroke='%23dc3545' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:linear-gradient(135deg,#1e3c72,#2a5298);min-height:100vh;display:flex;align-items:center;justify-content:center}.box{background:#fff;padding:40px;border-radius:12px;width:100%;max-width:400px}h1{color:#1e3c72;margin-bottom:30px;text-align:center}.fg{margin-bottom:20px}label{display:block;margin-bottom:8px;color:#666;font-weight:bold}input{width:100%;padding:12px;border:2px solid #ddd;border-radius:6px;font-size:16px}button{width:100%;padding:14px;background:#00d4ff;color:#fff;border:none;border-radius:6px;font-size:16px;cursor:pointer;font-weight:bold}.err{background:#f8d7da;color:#721c24;padding:12px;border-radius:6px;margin-bottom:20px;text-align:center}</style>
</head><body><div class="box"><h1>🎥 IPTV Detective</h1>
<?php if($login_error):?><div class="err"><?php echo $login_error;?></div><?php endif;?>
<form method="POST"><input type="hidden" name="login" value="1">
<div class="fg"><label>Username</label><input type="text" name="username" required autofocus></div>
<div class="fg"><label>Password</label><input type="password" name="password" required></div>
<button>Login</button></form></div></body></html><?php exit; }

$admin_id = $_SESSION['admin_id'] ?? 1;
$msg = ''; $msg_type = 'success';
$action = $_POST['action'] ?? '';
$tab = $_GET['tab'] ?? 'dashboard';

function upsert_scanned_host_for_baseline($db, $domain, $providerName) {
    if (!$domain) return;

    $originalUrl = preg_match('/^https?:\/\//i', $domain) ? $domain : 'http://' . $domain;
    $resolved_ip = gethostbyname($domain);
    if ($resolved_ip === $domain) {
        $resolved_ip = '0.0.0.0';
    }

    $providerName = $providerName ?: $domain;
    $stmt = $db->prepare(
        "INSERT INTO scanned_hosts (provider_name, provider_count, original_url, domain, resolved_ip, created_at)
         VALUES (?, 1, ?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE
            provider_name=VALUES(provider_name),
            original_url=VALUES(original_url),
            resolved_ip=VALUES(resolved_ip),
            updated_at=NOW()"
    );
    if ($stmt) {
        $stmt->bind_param("ssss", $providerName, $originalUrl, $domain, $resolved_ip);
        $stmt->execute();
        $stmt->close();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($action) {
        case 'create_baseline':
            $n=$_POST['service_name'];
            $d=$_POST['baseline_domain'];
            $st=$_POST['status']??'pending';
            $credentials_hash = md5(uniqid($d, true));
            
            $stmt = $db->prepare("INSERT INTO baseline_services (service_name, baseline_domain, credentials_hash, status, created_at) VALUES (?, ?, ?, ?, NOW())");
            $stmt->bind_param("ssss",$n,$d,$credentials_hash,$st);
            if ($stmt->execute()) {
                upsert_scanned_host_for_baseline($db, $d, $n);
                $msg = "✓ Baseline created!";
            } else {
                $msg = "Error: " . $stmt->error;
            }
            break;
        case 'delete_baseline':
            $stmt = $db->prepare("DELETE FROM baseline_services WHERE id=?");
            $stmt->bind_param("i", $_POST['id']);
            $stmt->execute();
            $msg = "✓ Deleted!";
            break;
        case 'edit_baseline':
            $n=$_POST['service_name'];
            $d=$_POST['baseline_domain'];
            $st=$_POST['status']??'pending';
            $id=$_POST['id'];
            
            // Update only the fields that should always exist
            $stmt = $db->prepare("UPDATE baseline_services SET service_name=?, baseline_domain=?, status=? WHERE id=?");
            $stmt->bind_param("sssi",$n,$d,$st,$id);
            
            if ($stmt->execute()) {
                $msg = "✓ Baseline updated!";
            } else {
                $msg = "Error: " . $stmt->error;
            }
            break;
        case 'delete_scan':
            $stmt = $db->prepare("DELETE FROM scanned_hosts WHERE id=?");
            $stmt->bind_param("i", $_POST['id']);
            $stmt->execute();
            $msg = "✓ Scan deleted!";
            break;
        case 'promote_to_baseline':
            $stmt = $db->prepare("SELECT * FROM scanned_hosts WHERE id=?");
            $stmt->bind_param("i", $_POST['id']);
            $stmt->execute();
            $scan = $stmt->get_result()->fetch_assoc();
            if ($scan) {
                $name = $scan['provider_name'] ?: $scan['domain'];
                // Insert with only the required fields that should exist on all servers
                try {
                    // Generate unique credentials_hash if needed
                    $credentials_hash = md5(uniqid($scan['domain'], true));
                    $stmt2 = $db->prepare("INSERT INTO baseline_services (service_name, baseline_domain, status, credentials_hash, created_at) VALUES (?, ?, 'approved', ?, NOW())");
                    if ($stmt2) {
                        $stmt2->bind_param("sss", $name, $scan['domain'], $credentials_hash);
                        $stmt2->execute();
                        upsert_scanned_host_for_baseline($db, $scan['domain'], $name);
                        $msg = "✓ Promoted to baseline!";
                    } else {
                        // Fallback without credentials_hash
                        $stmt2 = $db->prepare("INSERT INTO baseline_services (service_name, baseline_domain, status, created_at) VALUES (?, ?, 'approved', NOW())");
                        $stmt2->bind_param("ss", $name, $scan['domain']);
                        $stmt2->execute();
                        upsert_scanned_host_for_baseline($db, $scan['domain'], $name);
                        $msg = "✓ Promoted to baseline!";
                    }
                } catch (Exception $e) {
                    $msg = "Error: " . $e->getMessage();
                }
            }
            break;
        case 'create_alias':
            $stmt = $db->prepare("INSERT INTO service_aliases (baseline_id, alias_name) VALUES (?, ?)");
            $stmt->bind_param("is", $_POST['baseline_id'], $_POST['alias_name']);
            $stmt->execute();
            $msg = "✓ Alias added!";
            break;
        case 'delete_alias':
            $stmt = $db->prepare("DELETE FROM service_aliases WHERE id=?");
            $stmt->bind_param("i", $_POST['id']);
            $stmt->execute();
            $msg = "✓ Deleted!";
            break;
        case 'create_user':
            $stmt = $db->prepare("INSERT INTO admin_users (username, password_hash, role) VALUES (?, ?, ?)");
            $h = hash('sha256', $_POST['new_password']);
            $stmt->bind_param("sss", $_POST['new_username'], $h, $_POST['new_role']);
            $msg = $stmt->execute() ? "✓ User created!" : "Error: ".$db->error;
            break;
        case 'delete_user':
            if ($_POST['id'] != $admin_id) {
                $stmt = $db->prepare("DELETE FROM admin_users WHERE id=?");
                $stmt->bind_param("i", $_POST['id']);
                $stmt->execute();
                $msg = "✓ User deleted!";
            } else { $msg = "Cannot delete yourself!"; $msg_type = 'error'; }
            break;
    }
}

$stats = [];
$r=$db->query("SELECT COUNT(*) c FROM scanned_hosts"); $stats['scans']=$r->fetch_assoc()['c'];
$r=$db->query("SELECT COUNT(*) c FROM baseline_services"); $stats['baselines']=$r->fetch_assoc()['c'];
$r=$db->query("SELECT COUNT(*) c FROM baseline_services WHERE status='approved'"); $stats['approved']=$r->fetch_assoc()['c'];
$r=$db->query("SELECT COUNT(*) c FROM service_aliases"); $stats['aliases']=$r->fetch_assoc()['c'];
$r=$db->query("SELECT COUNT(DISTINCT domain) c FROM scanned_hosts"); $stats['domains']=$r->fetch_assoc()['c'];
$r=$db->query("SELECT COUNT(*) c FROM scanned_hosts WHERE panel_type != '' AND panel_type IS NOT NULL"); $stats['panels']=$r->fetch_assoc()['c'];

$data = [];
switch ($tab) {
    case 'scans': 
        $r=$db->query("SELECT * FROM scanned_hosts ORDER BY created_at DESC LIMIT 200"); 
        while($row=$r->fetch_assoc()) $data[]=$row; 
        break;
    case 'baselines': 
        $r=$db->query("SELECT * FROM baseline_services ORDER BY created_at DESC"); 
        while($row=$r->fetch_assoc()) $data[]=$row; 
        break;
    case 'aliases': 
        $r=$db->query("SELECT a.id, a.baseline_id, a.alias_name, b.service_name FROM service_aliases a LEFT JOIN baseline_services b ON a.baseline_id=b.id ORDER BY a.id DESC"); 
        while($row=$r->fetch_assoc()) $data[]=$row; 
        break;
    case 'users': 
        $r=$db->query("SELECT * FROM admin_users ORDER BY created_at DESC"); 
        while($row=$r->fetch_assoc()) $data[]=$row; 
        break;
    default: 
        $r=$db->query("SELECT * FROM scanned_hosts ORDER BY created_at DESC LIMIT 10"); 
        while($row=$r->fetch_assoc()) $data[]=$row; 
        break;
}

$bl=[]; $r=$db->query("SELECT id,service_name FROM baseline_services ORDER BY service_name"); while($row=$r->fetch_assoc()) $bl[]=$row;

function getVerdict($r) {
    $reseller_prob = $r['reseller_probability'] ?? 0;
    $is_reseller = $r['is_datacenter_reseller'] ?? 0;
    $is_upstream = $r['is_likely_upstream'] ?? 0;
    $upstream_score = $r['upstream_score'] ?? 0;
    $confidence = $r['confidence_score'] ?? 0;
    
    // Calculate reseller likelihood from all signals
    $signals = max($r['ns_reseller_confidence']??0, $r['cert_reseller_confidence']??0, $r['asn_reseller_confidence']??0);
    
    if ($is_upstream || $upstream_score >= 70) {
        return ['verdict' => '🔺 UPSTREAM', 'class' => 'upstream', 'desc' => 'Likely source/upstream provider'];
    } elseif ($is_reseller || $reseller_prob >= 70 || $signals >= 70) {
        return ['verdict' => '🔄 RESELLER', 'class' => 'reseller', 'desc' => 'High confidence reseller'];
    } elseif ($reseller_prob >= 40 || $signals >= 40) {
        return ['verdict' => '❓ POSSIBLE RESELLER', 'class' => 'maybe', 'desc' => 'Some reseller indicators'];
    } elseif ($confidence > 0 || $upstream_score > 0) {
        return ['verdict' => '🆕 UNIQUE/NEW', 'class' => 'direct', 'desc' => 'Appears to be independent'];
    } else {
        return ['verdict' => '❔ UNKNOWN', 'class' => 'unknown', 'desc' => 'Insufficient data'];
    }
}

function scoreBar($val, $label, $meaning) {
    if ($val == 0) return "";
    $bg = $val >= 70 ? '#dc3545' : ($val >= 40 ? '#ffc107' : '#28a745');
    return "<div class='score-row' title='$meaning'><span class='score-label'>$label</span><div class='score-bar'><div class='score-fill' style='width:{$val}%;background:$bg'></div></div><span class='score-val'>$val%</span></div>";
}
?><!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='grad' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' style='stop-color:%23dc3545;stop-opacity:1' /%3E%3Cstop offset='100%25' style='stop-color:%23c82333;stop-opacity:1' /%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M50 10 L75 25 L75 50 C75 75 50 90 50 90 C50 90 25 75 25 50 L25 25 Z' fill='url(%23grad)' stroke='white' stroke-width='2'/%3E%3Ccircle cx='50' cy='50' r='12' fill='white'/%3E%3Cpath d='M50 45 L50 55 M45 50 L55 50' stroke='%23dc3545' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:linear-gradient(135deg,#1e3c72,#2a5298);min-height:100vh;padding:20px;color:#333}.c{max-width:1700px;margin:0 auto}header{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center}h1{color:#1e3c72;font-size:22px}h2{color:#fff;margin:20px 0 15px}.logout{background:#dc3545;color:#fff;padding:8px 16px;border-radius:4px;text-decoration:none}.msg{padding:15px;margin-bottom:20px;border-radius:8px}.msg.success{background:#d4edda;color:#155724}.msg.error{background:#f8d7da;color:#721c24}.tabs{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}.tab{background:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;color:#333}.tab.active{background:#00d4ff;color:#fff}.badge{background:#dc3545;color:#fff;padding:2px 6px;border-radius:10px;font-size:11px;margin-left:5px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:15px;margin-bottom:30px}.card{background:#fff;padding:20px;border-radius:8px;border-left:4px solid #00d4ff}.card h3{color:#666;font-size:12px;margin-bottom:8px}.card .num{font-size:28px;font-weight:bold;color:#1e3c72}.panel{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px 6px;text-align:left;border-bottom:1px solid #eee}th{background:#f5f5f5;font-size:11px}tr:hover{background:#f9f9f9}.btn{padding:5px 10px;border:none;border-radius:4px;cursor:pointer;font-size:11px;margin:2px}.btn-success{background:#28a745;color:#fff}.btn-danger{background:#dc3545;color:#fff}.btn-primary{background:#00d4ff;color:#fff}.btn-sm{padding:3px 6px;font-size:10px}.status{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px}.status.pending{background:#fff3cd;color:#664d03}.status.approved{background:#d4edda;color:#155724}.fr{display:flex;gap:15px;margin-bottom:15px;flex-wrap:wrap}.fg{flex:1;min-width:180px}.fg label{display:block;margin-bottom:5px;font-weight:600;font-size:12px}.fg input,.fg select{width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px}.empty{text-align:center;padding:40px;color:#666}.role{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px}.role.admin{background:#d4edda;color:#155724}.role.moderator{background:#fff3cd;color:#664d03}.mono{font-family:monospace;font-size:10px}.trunc{max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.score-box{min-width:160px}.score-row{display:flex;align-items:center;gap:4px;margin-bottom:2px}.score-label{font-size:8px;width:32px;color:#666}.score-bar{flex:1;height:6px;background:#eee;border-radius:3px;overflow:hidden}.score-fill{height:100%;border-radius:3px}.score-val{font-size:8px;width:24px;text-align:right;font-weight:bold}
.verdict{display:inline-block;padding:4px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-bottom:4px}.verdict.upstream{background:#9b59b6;color:#fff}.verdict.reseller{background:#e74c3c;color:#fff}.verdict.maybe{background:#f39c12;color:#fff}.verdict.direct{background:#27ae60;color:#fff}.verdict.unknown{background:#95a5a6;color:#fff}
.verdict-desc{font-size:9px;color:#666;display:block}
.indicators{font-size:9px;color:#555;margin-top:4px}
</style>
</head><body><div class="c">
<header><h1>🎥 IPTV Detective</h1><div><span style="margin-right:15px">👤 <?php echo htmlspecialchars($_SESSION['admin_user']);?> <span class="role <?php echo $_SESSION['admin_role'];?>"><?php echo $_SESSION['admin_role'];?></span></span><a href="?logout=1" class="logout">Logout</a></div></header>
<?php if($msg):?><div class="msg <?php echo $msg_type;?>"><?php echo $msg;?></div><?php endif;?>
<div class="tabs">
<a href="?tab=dashboard" class="tab <?php echo $tab==='dashboard'?'active':'';?>">📊 Dashboard</a>
<a href="?tab=scans" class="tab <?php echo $tab==='scans'?'active':'';?>">🔍 Scans<span class="badge" style="background:#28a745"><?php echo $stats['scans'];?></span></a>
<a href="?tab=baselines" class="tab <?php echo $tab==='baselines'?'active':'';?>">🏷️ Baselines</a>
<a href="?tab=aliases" class="tab <?php echo $tab==='aliases'?'active':'';?>">🔗 Aliases</a>
<a href="?tab=users" class="tab <?php echo $tab==='users'?'active':'';?>">👥 Users</a>
</div>

<?php if($tab==='dashboard'):?>
<div class="grid">
<div class="card"><h3>Total Scans</h3><div class="num"><?php echo $stats['scans'];?></div></div>
<div class="card"><h3>Unique Domains</h3><div class="num"><?php echo $stats['domains'];?></div></div>
<div class="card"><h3>Panel Detected</h3><div class="num"><?php echo $stats['panels'];?></div></div>
<div class="card"><h3>Baselines</h3><div class="num"><?php echo $stats['baselines'];?></div></div>
<div class="card"><h3>Aliases</h3><div class="num"><?php echo $stats['aliases'];?></div></div>
</div>
<h2>Recent Scans</h2><div class="panel"><table><tr><th>Domain</th><th>Provider</th><th>Panel</th><th>Organization</th><th>🌍</th><th>Verdict</th><th>Date</th></tr>
<?php foreach($data as $r):
$v = getVerdict($r);
?><tr>
<td class="mono"><?php echo htmlspecialchars($r['domain']);?></td>
<td><?php echo htmlspecialchars($r['provider_name']?:'-');?></td>
<td><?php echo htmlspecialchars($r['panel_type']?:'-');?></td>
<td class="trunc"><?php echo htmlspecialchars($r['organization']?:'-');?></td>
<td><?php echo $r['country_code']?:'-';?></td>
<td><span class="verdict <?php echo $v['class'];?>"><?php echo $v['verdict'];?></span></td>
<td><?php echo date('M d H:i',strtotime($r['created_at']));?></td>
</tr><?php endforeach;?></table></div>
<?php endif;?>

<?php if($tab==='scans'):?>
<h2>All Scans (<?php echo count($data);?>)</h2><div class="panel"><table><tr><th>ID</th><th>Domain</th><th>Provider</th><th>Panel</th><th>IP</th><th>Org</th><th>🌍</th><th>Analysis</th><th>Reseller Signals</th><th>Evidence</th><th>Date</th><th></th></tr>
<?php foreach($data as $r):
$v = getVerdict($r);
$upstream=$r['upstream_score']??0;
$asn=$r['asn_reseller_confidence']??0;
$ns=$r['ns_reseller_confidence']??0;
$cert=$r['cert_reseller_confidence']??0;
$reg=$r['reg_pattern_confidence']??0;
$reseller_prob=$r['reseller_probability']??0;
?><tr>
<td>#<?php echo $r['id'];?></td>
<td class="mono"><?php echo htmlspecialchars($r['domain']);?></td>
<td><strong><?php echo htmlspecialchars($r['provider_name']?:'-');?></strong></td>
<td><?php echo htmlspecialchars($r['panel_type']?:'-');?></td>
<td class="mono"><?php echo htmlspecialchars($r['resolved_ip']?:'-');?></td>
<td class="trunc" title="<?php echo htmlspecialchars($r['organization']??'');?>"><?php echo htmlspecialchars(substr($r['organization']??'-',0,20));?></td>
<td><?php echo $r['country_code']?:'-';?></td>
<td>
<span class="verdict <?php echo $v['class'];?>"><?php echo $v['verdict'];?></span>
<span class="verdict-desc"><?php echo $v['desc'];?></span>
<?php if($r['is_likely_upstream']):?><div class="indicators">📡 Upstream detected</div><?php endif;?>
<?php if($r['is_datacenter_reseller']):?><div class="indicators">🏢 Datacenter reseller</div><?php endif;?>
</td>
<td class="score-box">
<?php if($reseller_prob > 0): ?><div class="score-row"><span class="score-label">Resell</span><div class="score-bar"><div class="score-fill" style="width:<?php echo $reseller_prob;?>%;background:<?php echo $reseller_prob>=70?'#dc3545':($reseller_prob>=40?'#ffc107':'#28a745');?>"></div></div><span class="score-val"><?php echo $reseller_prob;?>%</span></div><?php endif;?>
<?php echo scoreBar($ns, 'NS', 'Shared nameservers with known providers'); ?>
<?php echo scoreBar($cert, 'SSL', 'Shared SSL certificate with others'); ?>
<?php echo scoreBar($asn, 'ASN', 'Known reseller ASN/hosting'); ?>
<?php echo scoreBar($reg, 'Reg', 'Registration pattern matches resellers'); ?>
<?php echo scoreBar($upstream, 'Up', 'Upstream provider likelihood'); ?>
<?php if($ns==0 && $cert==0 && $asn==0 && $reg==0 && $upstream==0 && $reseller_prob==0):?><span style="font-size:9px;color:#999">No signals</span><?php endif;?>
</td>
<td class="trunc" title="<?php echo htmlspecialchars($r['relationship_reasons']?:'');?>"><?php echo htmlspecialchars($r['relationship_reasons']?:'No evidence');?></td>
<td><?php echo date('M d',strtotime($r['created_at']));?></td>
<td>
<form method="POST" style="display:inline"><input type="hidden" name="action" value="promote_to_baseline"><input type="hidden" name="id" value="<?php echo $r['id'];?>"><button class="btn btn-primary btn-sm" title="Promote to Baseline">↑</button></form>
<form method="POST" style="display:inline" onsubmit="return confirm('Delete?')"><input type="hidden" name="action" value="delete_scan"><input type="hidden" name="id" value="<?php echo $r['id'];?>"><button class="btn btn-danger btn-sm">×</button></form>
</td>
</tr><?php endforeach;?></table></div>

<div style="background:#fff;padding:15px;border-radius:8px;margin-top:20px">
<h3 style="margin-bottom:10px">Legend</h3>
<div style="display:flex;gap:20px;flex-wrap:wrap;font-size:12px">
<div><span class="verdict upstream">🔺 UPSTREAM</span> Source/main provider</div>
<div><span class="verdict reseller">🔄 RESELLER</span> High confidence reseller</div>
<div><span class="verdict maybe">❓ POSSIBLE</span> Some reseller signals</div>
<div><span class="verdict direct">🆕 UNIQUE/NEW</span> Appears independent</div>
<div><span class="verdict unknown">❔ UNKNOWN</span> Insufficient data</div>
</div>
<div style="margin-top:10px;font-size:11px;color:#666">
<strong>Signals:</strong> NS=Shared Nameservers, SSL=Shared Certificates, ASN=Known Reseller Hosting, Reg=Registration Pattern, Up=Upstream Score
</div>
</div>
<?php endif;?>

<?php if($tab==='baselines'):?>
<h2>Create Baseline</h2><div class="panel"><form method="POST"><input type="hidden" name="action" value="create_baseline">
<div class="fr"><div class="fg"><label>Name</label><input name="service_name" required></div><div class="fg"><label>Domain</label><input name="baseline_domain" required></div><div class="fg"><label>Channels</label><input type="number" name="channel_count" value="0"></div></div>
<div class="fr"><div class="fg"><label>Panel Type</label><input name="panel_type" placeholder="xstream, xtream, etc"></div><div class="fg"><label>EPG</label><input name="epg_source"></div><div class="fg"><label>Status</label><select name="status"><option value="approved">Approved</option><option value="pending">Pending</option></select></div></div>
<button class="btn btn-success">+ Create</button></form></div>
<h2>All Baselines (<?php echo count($data);?>)</h2><div class="panel"><?php if(empty($data)):?><div class="empty">None yet - add baselines or promote from scans</div><?php else:?><table><tr><th>ID</th><th>Name</th><th>Domain</th><th>Panel</th><th>Channels</th><th>Status</th><th>Created</th><th></th></tr><?php foreach($data as $r):?><tr><td>#<?php echo $r['id'];?></td><td><strong><?php echo htmlspecialchars($r['service_name']);?></strong></td><td class="mono"><?php echo htmlspecialchars($r['baseline_domain']??'');?></td><td><?php echo htmlspecialchars($r['panel_type']??'-');?></td><td><?php echo $r['channel_count']??0;?></td><td><span class="status <?php echo $r['status']??'pending';?>"><?php echo $r['status']??'pending';?></span></td><td><?php echo date('M d Y',strtotime($r['created_at']??'now'));?></td><td style="display:flex;gap:4px"><button type="button" class="btn btn-primary btn-sm" onclick="editBaseline(<?php echo htmlspecialchars(json_encode($r)); ?>)">Edit</button><form method="POST" style="display:inline" onsubmit="return confirm('Delete?')"><input type="hidden" name="action" value="delete_baseline"><input type="hidden" name="id" value="<?php echo $r['id'];?>"><button class="btn btn-danger btn-sm">Del</button></form></td></tr><?php endforeach;?></table><?php endif;?></div>
<?php endif;?>

<?php if($tab==='aliases'):?>
<h2>Add Alias</h2><div class="panel"><form method="POST"><input type="hidden" name="action" value="create_alias">
<div class="fr"><div class="fg"><label>Baseline</label><select name="baseline_id" required><option value="">--</option><?php foreach($bl as $b):?><option value="<?php echo $b['id'];?>"><?php echo htmlspecialchars($b['service_name']);?></option><?php endforeach;?></select></div><div class="fg"><label>Alias Name</label><input name="alias_name" required></div></div>
<button class="btn btn-success">+ Add</button></form></div>
<h2>All Aliases (<?php echo count($data);?>)</h2><div class="panel"><?php if(empty($data)):?><div class="empty">None</div><?php else:?><table><tr><th>ID</th><th>Baseline</th><th>Alias</th><th></th></tr><?php foreach($data as $r):?><tr><td>#<?php echo $r['id'];?></td><td><?php echo htmlspecialchars($r['service_name']??'(deleted)');?></td><td><strong><?php echo htmlspecialchars($r['alias_name']??'');?></strong></td><td><form method="POST" style="display:inline"><input type="hidden" name="action" value="delete_alias"><input type="hidden" name="id" value="<?php echo $r['id'];?>"><button class="btn btn-danger btn-sm">Del</button></form></td></tr><?php endforeach;?></table><?php endif;?></div>
<?php endif;?>

<?php if($tab==='users'):?>
<h2>Create User</h2><div class="panel"><form method="POST"><input type="hidden" name="action" value="create_user">
<div class="fr"><div class="fg"><label>Username</label><input name="new_username" required></div><div class="fg"><label>Password</label><input type="password" name="new_password" required></div><div class="fg"><label>Role</label><select name="new_role"><option value="admin">Admin</option><option value="moderator">Moderator</option><option value="viewer">Viewer</option></select></div></div>
<button class="btn btn-success">+ Create</button></form></div>
<h2>All Users</h2><div class="panel"><?php if(empty($data)):?><div class="empty">None</div><?php else:?><table><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th><th>Last Login</th><th></th></tr><?php foreach($data as $r):?><tr><td>#<?php echo $r['id'];?></td><td><strong><?php echo htmlspecialchars($r['username']??'');?></strong><?php if($r['id']==$admin_id):?> (you)<?php endif;?></td><td><span class="role <?php echo $r['role']??'viewer';?>"><?php echo $r['role']??'viewer';?></span></td><td><?php echo date('M d Y',strtotime($r['created_at']??'now'));?></td><td><?php echo (!empty($r['last_login']))?date('M d H:i',strtotime($r['last_login'])):'Never';?></td><td><?php if($r['id']!=$admin_id):?><form method="POST" style="display:inline" onsubmit="return confirm('Delete?')"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="id" value="<?php echo $r['id'];?>"><button class="btn btn-danger btn-sm">Del</button></form><?php else:?>-<?php endif;?></td></tr><?php endforeach;?></table><?php endif;?></div>
<?php endif;?>

<div id="editModal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:1000;align-items:center;justify-content:center">
<div style="background:white;padding:20px;border-radius:8px;max-width:500px;width:90%">
<h3>Edit Baseline</h3>
<form method="POST" id="editForm">
<input type="hidden" name="action" value="edit_baseline">
<input type="hidden" name="id" id="editId">
<div class="fr"><div class="fg"><label>Name</label><input name="service_name" id="editName" required></div><div class="fg"><label>Domain</label><input name="baseline_domain" id="editDomain" required></div></div>
<div class="fr"><div class="fg"><label>Channels</label><input type="number" name="channel_count" id="editChannels" value="0"></div><div class="fg"><label>Panel Type</label><input name="panel_type" id="editPanel" placeholder="xstream, xtream, etc"></div></div>
<div class="fr"><div class="fg"><label>EPG</label><input name="epg_source" id="editEPG"></div><div class="fg"><label>Status</label><select name="status" id="editStatus"><option value="approved">Approved</option><option value="pending">Pending</option></select></div></div>
<div style="display:flex;gap:10px;margin-top:15px">
<button type="submit" class="btn btn-success">Save Changes</button>
<button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
</div>
</form>
</div>
</div>

<script>
function editBaseline(baseline) {
  document.getElementById('editId').value = baseline.id;
  document.getElementById('editName').value = baseline.service_name || '';
  document.getElementById('editDomain').value = baseline.baseline_domain || '';
  document.getElementById('editChannels').value = baseline.channel_count || 0;
  document.getElementById('editPanel').value = baseline.panel_type || '';
  document.getElementById('editEPG').value = baseline.epg_source || '';
  document.getElementById('editStatus').value = baseline.status || 'pending';
  document.getElementById('editModal').style.display = 'flex';
}

function closeEditModal() {
  document.getElementById('editModal').style.display = 'none';
}

// Close modal when clicking outside
document.getElementById('editModal')?.addEventListener('click', function(e) {
  if(e.target === this) closeEditModal();
});
</script>

</div></body></html><?php $db->close();?>