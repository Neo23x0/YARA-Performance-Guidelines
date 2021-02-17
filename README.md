# YARA-Performance-Guidelines
A guide on how to write fast and memory friendly YARA rules

When creating your rules for YARA keep in mind the following guidelines in order to get the best performance from them.
This guide is based on ideas and recommendations by Victor M. Alvarez and WXS.

- Revision 1.4, October 2020, applies to all YARA versions higher than 3.7

## Atoms

YARA extracts from the strings short substrings up to 4 bytes long that are called "atoms". Those atoms can be extracted from any place within the string, and YARA searches for those atoms while scanning the file, if it finds one of the atoms then it verifies that the string actually matches.

For example, consider this strings:

```
/abc.*cde/
``` 
=> posible atoms are `abc` and `cde`, either one or the other can be used

```
/(one|two)three/
```
=> posible atoms are `one`, `two` and `three`, we can search for `three` alone, or for both `one` and `two`

YARA does its best effort to select the best atoms from each string, for example:

```
{ 00 00 00 00 [1-4] 01 02 03 04 }
```
=> here YARA uses the atom `01 02 03 04`, because `00 00 00 00` is too common

```
{ 01 02 [1-4] 01 02 03 04 }
```
=> `01 02 03 04` is preferred over `01 02` because it's longer

So, the important point is that strings should contain good atoms.
These are bad strings because they contain either too short or too common atoms:

```
{00 00 00 00 [1-2] FF FF [1-2] 00 00 00 00}
{AB  [1-2] 03 21 [1-2] 01 02}
/a.*b/
/a(c|d)/
```

The worst strings are those that don't contain any atoms at all, like:

```
/\w.*\d/
/[0-9]+\n/
```

This regular expression don't contain any fixed substring that can be used as atom, so it must be evaluated at every offset of the file to see if it matches there.

## Too Many Loop Iterations

Another good import recommendation is to avoid for [loops](https://yara.readthedocs.io/en/v3.9.0/writingrules.html#iterating-over-string-occurrences) with too many iterations, specially of the statement within the loop is too complex, for example:

```
strings:
	$a = {00 00}
condition:
	for all i in (1..#a) : (@a[i] < 10000)
```

This rule has two problems. The first is that the string $a is too common, the second one is that because $a is too common #a can be too high and can be evaluated thousands of times.

This other condition is also inefficient because the number of iterations depends on filesize, which can be also very high:

```
for all i in (1..filesize) : ($a at i)
```

## Magic Module

Avoid using the ["magic" module](https://yara.readthedocs.org/en/v3.3.0/modules/magic.html) which is not available on the Windows platform. Using the "magic" module slows down scanning but provides exact matches.

Custom GIF magic header definition:

```
rule gif_1 {
  condition:
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961) or
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3761)
}
```

Using the "[magic](https://yara.readthedocs.io/en/v3.9.0/modules/magic.html)" module:

```
import "magic"
rule gif_2 {
  condition:
    magic.mime_type() == "image/gif"
}
```

## Too Short Strings 

Avoid defining too short strings. Any string with less than 4 bytes will probably appear in a lot of files OR as uniform content in an XORed file.
  
## Uniform Content

Some strings are long enough but shouldn't be used due to a different reason - uniformity. These are some examples for strings that shouldn't be used as they could cause too many matches in files. 

```
$s1 = "22222222222222222222222222222222222222222222222222222222222222" ascii
$s2 = "\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20" ascii  // wide formatted spaces
```

Error message would look like:
```
error scanning yara-killer.dat: string "$mz" in rule "shitty_mz" caused too many matches
```

## String Advices

Try to describe string definitions as narrow as possible. Avoid the "nocase" attribute if possible, because many atoms will be generated and searched for (higher memory usage, more iterations). Remember, in the absence of modifiers "ascii" is assumed by default. The posible combinations are:

**LOW** - only one [atom](#atoms) is generated
```
$s1 = "cmd.exe"		       // (ascii only)
$s2 = "cmd.exe" ascii          // (ascii only, same as $s1)
$s3 = "cmd.exe" wide           // (UTF-16 only)
$s4 = "cmd.exe" ascii wide     // (both ascii and UTF-16) two atoms will be generated 
$s5 = { 63 6d 64 2e 65 78 65 } // ascii char code in hex
```

**HIGH** - many [atoms](#atoms) will be generated
```
$s5 = "cmd.exe" nocase      (all different cases, e.g. "Cmd.exe", "cMd.exe", "cmD.exe" ..)
```

## Regular Expressions

Use expressions only when necessary. [Regular expression](https://yara.readthedocs.io/en/v3.9.0/writingrules.html#regular-expressions) evaluation is inherently slower than plain string matching and consumes a **significant amount of memory**. Don't use them if hex strings with jumps and wild-cards can solve the problem.

If you have to use regular expressions avoid greedy `.*` and even reluctant quantifiers `.*?`. Instead use exact numbers like `.{1,30}` or even `.{1,3000}`.

Also try to include long sequences of strings that could serve as ankers in the matching progress. Again, the longer the better. 

BAD
```
$s1 = /http:\/\/[.]*\.hta/
```

BETTER
```
$s1 = /http:\/\/[a-z0-9\.\/]{3,70}\.hta/
```

BEST
```
$s1 = /mshta\.exe http:\/\/[a-z0-9\.\/]{3,70}\.hta/
```

## Conditions and Short-Circuit Evaluation

Try to write condition statements in which the elements that are most likely to be "False" are placed first. The condition is evaluated from left to right. The sooner the engine identifies that a rule is not satisfied the sooner it can skip the current rule and evaluate the next one. The speed improvement caused by this way to order the condition statements depends on the difference in necessary CPU cycles to process each of the satements. If all statements are more or less equally expensive, reordering the statements causes no noticeable improvement. If one of the statements can be processed very fast it is recommended to place it first in order to skip the expensive statement evaluation in cases in which the first statment is FALSE. 

Changing the order in the following statement does not cause a significant improvement: 

```
$string1 and $string2 and uint16(0) == 0x5A4D
```

However, if the execution time of the statements is very different, reordering in order to trigger the short-circuit will improve the scan speed significantly:

**SLOW**   
```
EXPENSIVE and CHEAP
math.entropy(0, filesize) > 7.0 and uint16(0) == 0x5A4D
```

**FAST**
```
CHEAP and EXPENSIVE
uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0
```

Short-circuit evaluation was introduced to help optimizing expensive sentences, particularly "for" sentences. Some people were using conditions like the one in the following example:

```
strings:
	$mz = "MZ"
	...
condition:
	$mz at 0 and for all i in (1..filesize) : ( whatever )
```

Because filesize can be a very big number, "whatever" can be executed a lot of times, slowing down the execution. Now, with short-circuit evaluation, the "for" sentence will be executed only if the first part of the condition is met, so, this rule will be slow only for MZ files. An additional improvement could be: 

```
$mz at 0 and filesize < 100K and for all i in (1..filesize) : ( whatever )
```

This way a higher bound to the number of iterations is set.

This "short-circuit" evaluation is applied since YARA version 3.4.
