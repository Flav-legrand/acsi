<?php
/**
 * Découpe un script SQL en instructions.
 * Fonction partagée par install-apps.php, install.php et les scripts
 * de maintenance : le code est identique à install_split_sql() afin
 * qu'un même fichier .sql s'exécute partout de la même façon.
 */
function apps_split_sql(string $sql): array
{
    $statements = [];
    $cur   = '';
    $len  = strlen($sql);
    $inS = $inD = $inB = $inLine = $inBlock = false;
    for ($i = 0; $i < $len; $i++) {
        $ch   = $sql[$i];
        $next = $i + 1 < $len ? $sql[$i + 1] : '';
        if ($inLine)  { if ($ch === "\n") { $inLine = false; $cur .= $ch; } continue; }
        if ($inBlock) { if ($ch === '*' && $next === '/') { $inBlock = false; $i++; } continue; }
        if ($inS) {
            $cur .= $ch;
            if ($ch === '\\') { if ($next !== '') { $cur .= $next; $i++; } continue; }
            if ($ch === "'") { if ($next === "'") { $cur .= $next; $i++; } else { $inS = false; } }
            continue;
        }
        if ($inD) {
            $cur .= $ch;
            if ($ch === '\\') { if ($next !== '') { $cur .= $next; $i++; } continue; }
            if ($ch === '"') { if ($next === '"') { $cur .= $next; $i++; } else { $inD = false; } }
            continue;
        }
        if ($inB) { $cur .= $ch; if ($ch === '`') { $inB = false; } continue; }
        if ($ch === '-' && $next === '-') { $inLine = true; $i++; continue; }
        if ($ch === '/' && $next === '*') { $inBlock = true; $i++; continue; }
        if ($ch === "'") { $inS = true; $cur .= $ch; continue; }
        if ($ch === '"') { $inD = true; $cur .= $ch; continue; }
        if ($ch === '`') { $inB = true; $cur .= $ch; continue; }
        if ($ch === ';') { $statements[] = trim($cur); $cur = ''; continue; }
        $cur .= $ch;
    }
    if (trim($cur) !== '') { $statements[] = trim($cur); }
    return $statements;
}
