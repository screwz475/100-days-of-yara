/*

Результат изучения средства автоматизации написания YARA yarGen =) 
И это не потому что мне лень!!

YARA Rule Set
Author: yarGen Rule Generator
Date: 2026-09-04
Identifier: file2
Reference: https://github. com/Neo23x0/yarGen
*/

/* Rule Set */

rule sample_named_1ndex {
  meta:
    description = "file 1ndex. php"
    author = "yarGen Rule Generator"
    reference = "https://github.com/Neo23x0/yarGen"
    date = "2026-09-04"
    hash1 = "53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf"
  strings:
    $x1 = "var Zepto=function() {function G(a) {return a == null?String(a) : z[A.call (a) ] | |\"object\"}function H(a) {return G(a) == \"function\"}fun" ascii
    $s2 = "return (res = new RegExp(' ( ?: ^|; )'+ encodeURIComponent (key) + '=([^; ]*) ') .exec (document. cookie) ) ? (res[1]) : null;" fullword ascii
    $s3 = "$cmd = trim(execute(\"ps -p \".$pid));" fullword ascii
    $s4 = "$cmd = execute(\"taskkill /F /PID \".$pid) ;" fullword ascii
    $s5 = "$buff = execute(\"wget \".$url.\" -0 \".$saveas);" fullword ascii
    $s6 = "$buff = execute(\"curl \".$url. \" -o \".$saveas) ;" fullword ascii
    $s7= "(d=\"0\"+d) ;dt2=y+m+d; return dt1 == dt2?0:dt1<dt2 ?- 1:1} , r : function(a, b) {for(var c=0, e=a. length-1, g=h ;g; ) {for(var g=j, f=c; f<e;++f)0" ascii
    $s8 = "$cmd = execute(\"kill -9 \".$pid);" fullword ascii
    $s9 = "$cmd = execute(\"tasklist /FI \\\"PID eq \".$pid.\"\\\"\");" fullword ascii
    $s10 = "$body = preg_replace(\"/<a_href=\\\"http:\\/\\/www.zend.com\\/( .*? )<\\/a>/\", \"\", $body) ;" fullword ascii
    $s11 = "execute(\"tar xf \\\"\".basename($archive) . \"\\\" -C \\\"\".$target. \"\\\"\");" fullword ascii
    $s12 = "ngs . mimeType | | xhr . getResponseHeader (\"content-type\") ) , result=xhr. responseText; try{dataType == \"script\ "? (1, eval) (result) : dataTyp" ascii
    $s13 = "execute(\"tar xzf \\\"\".basename($archive) .\"\\\" -C \\\"\".$target.\"\\\"\");" fullword ascii
    $s14 = "$check = strtolower(execute(\"python -h\"));" fullword ascii
    $s15 = "$check = strtolower(execute(\"ruby -h\"));" fullword ascii
    $s16 = "$check = strtolower(execute(\"java -help\"));" fullword ascii
    $s17 = "$buff = execute(\"lwp-download \".$url. \" \".$saveas) ;" fullword ascii
    $s18 = "$check = strtolower(execute(\"javac -help\"));" fullword ascii
    $s19 = "/* Zepto v1.1.2 - zepto event ajax form ie - zeptojs. com/license */" fullword ascii
    $s20 = "$check = strtolower(execute(\"nodejs -h\"));" fullword ascii
  condition:
    uint16(0) == 0x3f3c and filesize < 700KB and
    1 of ($x*) and 4 of them
}
