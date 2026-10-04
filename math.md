# Mathematics Learning Guide

Mathematics is a language for quantities, patterns, shapes, change, uncertainty, and logical reasoning. This guide builds from elementary arithmetic to advanced high-school and early-university mathematics. Each topic gives the core idea, the rule, and a short example.

## Table of Contents

### Stage 1: Arithmetic Foundations
1. [Mathematical Language](#mathematical-language)
2. [Numbers and Place Value](#numbers-and-place-value)
3. [The Four Operations](#the-four-operations)
4. [Order of Operations](#order-of-operations)
5. [Factors, Multiples, and Primes](#factors-multiples-and-primes)
6. [Fractions](#fractions)
7. [Decimals](#decimals)
8. [Percentages](#percentages)
9. [Ratios, Rates, and Proportions](#ratios-rates-and-proportions)
10. [Units and Measurement](#units-and-measurement)

### Stage 2: Pre-Algebra
11. [Negative Numbers](#negative-numbers)
12. [Powers and Roots](#powers-and-roots)
13. [Scientific Notation](#scientific-notation)
14. [Variables and Expressions](#variables-and-expressions)
15. [Equations](#equations)
16. [Inequalities](#inequalities)
17. [Absolute Value](#absolute-value)
18. [Patterns and Sequences](#patterns-and-sequences)

### Stage 3: Algebra
19. [Linear Equations](#linear-equations)
20. [Lines and Slope](#lines-and-slope)
21. [Systems of Equations](#systems-of-equations)
22. [Polynomials](#polynomials)
23. [Factoring](#factoring)
24. [Quadratic Equations](#quadratic-equations)
25. [Rational Expressions](#rational-expressions)
26. [Radicals and Rational Exponents](#radicals-and-rational-exponents)
27. [Exponential and Logarithmic Equations](#exponential-and-logarithmic-equations)

### Stage 4: Geometry
28. [Geometry Basics](#geometry-basics)
29. [Angles and Parallel Lines](#angles-and-parallel-lines)
30. [Triangles](#triangles)
31. [Congruence and Similarity](#congruence-and-similarity)
32. [Polygons](#polygons)
33. [Circles](#circles)
34. [Coordinate Geometry](#coordinate-geometry)
35. [Transformations](#transformations)
36. [Area, Surface Area, and Volume](#area-surface-area-and-volume)

### Stage 5: Functions and Precalculus
37. [Functions](#functions)
38. [Graph Transformations](#graph-transformations)
39. [Linear and Quadratic Functions](#linear-and-quadratic-functions)
40. [Polynomial and Rational Functions](#polynomial-and-rational-functions)
41. [Exponential and Logarithmic Functions](#exponential-and-logarithmic-functions)
42. [Piecewise, Composite, and Inverse Functions](#piecewise-composite-and-inverse-functions)
43. [Advanced Sequences and Series](#advanced-sequences-and-series)

### Stage 6: Trigonometry and Analytic Geometry
44. [Right-Triangle Trigonometry](#right-triangle-trigonometry)
45. [Radians and the Unit Circle](#radians-and-the-unit-circle)
46. [Trigonometric Graphs](#trigonometric-graphs)
47. [Identities and Equations](#identities-and-equations)
48. [Laws of Sines and Cosines](#laws-of-sines-and-cosines)
49. [Conic Sections](#conic-sections)
50. [Vectors](#vectors)
51. [Complex Numbers](#complex-numbers)

### Stage 7: Probability and Statistics
52. [Descriptive Statistics](#descriptive-statistics)
53. [Counting Principles](#counting-principles)
54. [Probability](#probability)
55. [Conditional Probability and Bayes' Theorem](#conditional-probability-and-bayes-theorem)
56. [Random Variables and Distributions](#random-variables-and-distributions)
57. [Normal and Binomial Distributions](#normal-and-binomial-distributions)
58. [Sampling and Confidence Intervals](#sampling-and-confidence-intervals)
59. [Hypothesis Testing](#hypothesis-testing)
60. [Correlation and Regression](#correlation-and-regression)

### Stage 8: Discrete Mathematics and Number Theory
61. [Sets](#sets)
62. [Logic](#logic)
63. [Proof Methods](#proof-methods)
64. [Mathematical Induction](#mathematical-induction)
65. [Relations and Graphs](#relations-and-graphs)
66. [Prime Numbers and Divisibility](#prime-numbers-and-divisibility)
67. [Modular Arithmetic](#modular-arithmetic)

### Stage 9: Calculus
68. [Limits and Continuity](#limits-and-continuity)
69. [Derivatives](#derivatives)
70. [Applications of Derivatives](#applications-of-derivatives)
71. [Integrals](#integrals)
72. [Applications of Integrals](#applications-of-integrals)
73. [Integration Techniques](#integration-techniques)
74. [Differential Equations](#differential-equations)
75. [Infinite Series](#infinite-series)
76. [Multivariable Calculus](#multivariable-calculus)

### Stage 10: Linear Algebra and Applied Mathematics
77. [Matrices](#matrices)
78. [Linear Systems and Row Reduction](#linear-systems-and-row-reduction)
79. [Determinants and Inverses](#determinants-and-inverses)
80. [Vector Spaces](#vector-spaces)
81. [Eigenvalues and Eigenvectors](#eigenvalues-and-eigenvectors)
82. [Optimization](#optimization)
83. [Numerical Methods and Error](#numerical-methods-and-error)
84. [Problem-Solving Strategy](#problem-solving-strategy)
85. [Essential Formula Sheet](#essential-formula-sheet)
86. [Practice Problems](#practice-problems)

---

# Stage 1: Arithmetic Foundations

## Mathematical Language

Mathematics becomes easier when every symbol has a precise meaning.

| Symbol | Meaning | Example |
|---|---|---|
| $=$ | equal to | $2+3=5$ |
| $\ne$ | not equal to | $4\ne7$ |
| $<$, $>$ | less than, greater than | $3<8$ |
| $\le$, $\ge$ | less/greater than or equal to | $x\ge2$ |
| $\approx$ | approximately equal | $\pi\approx3.14$ |
| $\pm$ | plus or minus | $x=\pm4$ |
| $\in$ | is an element of | $3\in\mathbb{Z}$ |
| $\therefore$ | therefore | $x=2\therefore x^2=4$ |

**Number sets:**

- Natural numbers: $\mathbb{N}=\{1,2,3,\ldots\}$; some definitions include $0$.
- Whole numbers: $0,1,2,3,\ldots$
- Integers: $\mathbb{Z}=\{\ldots,-2,-1,0,1,2,\ldots\}$
- Rational numbers: $\mathbb{Q}$, numbers expressible as $a/b$ where $b\ne0$.
- Irrational numbers: cannot be written as a fraction, such as $\sqrt2$ and $\pi$.
- Real numbers: $\mathbb{R}$, all rational and irrational numbers.
- Complex numbers: $\mathbb{C}$, numbers of the form $a+bi$.

## Numbers and Place Value

In base 10, each position is ten times the position to its right.

$$4{,}582.37=4(1000)+5(100)+8(10)+2+3(0.1)+7(0.01)$$

**Rounding:** Look one digit to the right of the desired place. If it is $5$ or more, round up.

Example: $8.376$ rounded to the nearest hundredth is $8.38$.

**Comparing numbers:** Align decimal places, then compare from left to right.

Example: $3.405>3.399$ because the tenths tie, but $4$ hundredths is greater than $3$.

## The Four Operations

| Operation | Meaning | Example |
|---|---|---|
| Addition | combine | $17+8=25$ |
| Subtraction | find a difference | $17-8=9$ |
| Multiplication | repeated scaling | $6\cdot4=24$ |
| Division | split or form a ratio | $24\div6=4$ |

**Properties:**

- Commutative: $a+b=b+a$ and $ab=ba$.
- Associative: $(a+b)+c=a+(b+c)$ and $(ab)c=a(bc)$.
- Distributive: $a(b+c)=ab+ac$.
- Identity: $a+0=a$ and $a\cdot1=a$.
- Inverse: $a+(-a)=0$ and $a\cdot(1/a)=1$ when $a\ne0$.
- Division by zero is undefined.

Example: $7(10+2)=70+14=84$.

## Order of Operations

Use grouping, exponents, multiplication/division, then addition/subtraction. Operations at the same level go left to right.

$$3+2(5^2-21)=3+2(25-21)=3+8=11$$

Common mistake: $20\div5\cdot2=4\cdot2=8$, not $2$.

## Factors, Multiples, and Primes

- A **factor** divides a number exactly. Factors of $12$: $1,2,3,4,6,12$.
- A **multiple** is the result of multiplying. Multiples of $5$: $5,10,15,\ldots$
- A **prime** has exactly two positive factors: $1$ and itself.
- A **composite** has more than two positive factors.

**Prime factorization:**

$$84=2\cdot42=2^2\cdot21=2^2\cdot3\cdot7$$

**Greatest common factor:** Use the smallest shared prime powers.

$$18=2\cdot3^2,\quad24=2^3\cdot3\quad\Rightarrow\quad\gcd(18,24)=2\cdot3=6$$

**Least common multiple:** Use the largest powers appearing.

$$\operatorname{lcm}(18,24)=2^3\cdot3^2=72$$

## Fractions

A fraction $a/b$ means $a\div b$, where $b\ne0$.

**Simplify:** Divide numerator and denominator by their GCF.

$$\frac{18}{24}=\frac{3}{4}$$

**Add or subtract:** Use a common denominator.

$$\frac{2}{3}+\frac{1}{4}=\frac{8}{12}+\frac{3}{12}=\frac{11}{12}$$

**Multiply:** Multiply straight across, simplifying when possible.

$$\frac{3}{5}\cdot\frac{10}{9}=\frac{30}{45}=\frac{2}{3}$$

**Divide:** Multiply by the reciprocal.

$$\frac{3}{4}\div\frac{2}{5}=\frac{3}{4}\cdot\frac{5}{2}=\frac{15}{8}$$

**Mixed number:** $2\frac35=(2\cdot5+3)/5=13/5$.

## Decimals

Decimals are fractions whose denominators are powers of ten.

$$0.375=\frac{375}{1000}=\frac38$$

**Fraction to decimal:** Divide numerator by denominator.

$$\frac58=5\div8=0.625$$

**Repeating decimal:** $0.\overline3=1/3$.

For multiplication, multiply as whole numbers and restore the total decimal places:

$$1.2\cdot0.35=0.420=0.42$$

## Percentages

Percent means “per hundred”: $p\%=p/100$.

**Conversions:**

$$35\%=0.35=\frac{35}{100}=\frac7{20}$$

**Find a percentage of an amount:**

$$18\%\text{ of }250=0.18(250)=45$$

**Find what percentage one number is of another:**

$$\frac{\text{part}}{\text{whole}}\cdot100\%=\frac{30}{120}\cdot100\%=25\%$$

**Find the original whole:**

If $42$ is $70\%$ of $x$, then $0.70x=42$, so $x=60$.

**Percentage change:**

$$\%\text{ change}=\frac{\text{new}-\text{original}}{\text{original}}\cdot100\%$$

From $80$ to $92$: $(92-80)/80=0.15=15\%$ increase.

**Increase or decrease by a percentage:**

$$\text{new}=\text{original}(1\pm r)$$

A $15\%$ discount on $\$80$: $80(1-0.15)=\$68$.

**Successive changes multiply:** A $20\%$ rise then a $20\%$ fall gives $1.20(0.80)=0.96$, a net $4\%$ decrease.

**Simple interest:** $I=Prt$.

Example: $\$1000$ at $5\%$ for $3$ years gives $I=1000(0.05)(3)=\$150$.

**Compound growth:** $A=P(1+r)^t$ for annual compounding.

Example: $\$1000$ at $5\%$ for $3$ years gives $1000(1.05)^3\approx\$1157.63$.

## Ratios, Rates, and Proportions

A ratio compares quantities: $12:8=3:2$. A rate compares different units: $150$ km in $3$ h is $50$ km/h.

**Proportion:** Two equal ratios.

$$\frac35=\frac{x}{20}\quad\Rightarrow\quad3(20)=5x\quad\Rightarrow\quad x=12$$

**Direct variation:** $y=kx$. If $y=15$ when $x=3$, then $k=5$ and $y=5x$.

**Inverse variation:** $y=k/x$. If doubling $x$ halves $y$, the product $xy=k$ stays constant.

**Scale:** On a $1:50{,}000$ map, $2$ cm represents $100{,}000$ cm $=1$ km.

## Units and Measurement

Multiply by a conversion factor equal to $1$ so unwanted units cancel.

$$72\frac{\text{km}}{\text{h}}\cdot\frac{1000\text{ m}}{1\text{ km}}\cdot\frac{1\text{ h}}{3600\text{ s}}=20\frac{\text{m}}{\text{s}}$$

**Metric prefixes:**

| Prefix | Symbol | Factor |
|---|---|---|
| kilo | k | $10^3$ |
| centi | c | $10^{-2}$ |
| milli | m | $10^{-3}$ |
| micro | $\mu$ | $10^{-6}$ |
| nano | n | $10^{-9}$ |

For area and volume, square or cube the conversion:

$$1\text{ m}^2=(100\text{ cm})^2=10{,}000\text{ cm}^2$$

---

# Stage 2: Pre-Algebra

## Negative Numbers

On a number line, numbers farther right are greater. The opposite of $a$ is $-a$.

**Sign rules:**

- Same-sign addition: add magnitudes and keep the sign. $-4+(-7)=-11$.
- Different-sign addition: subtract magnitudes and keep the sign of the larger magnitude. $-9+5=-4$.
- Subtracting means adding the opposite. $6-(-3)=9$.
- Same signs multiply/divide to positive; different signs give negative.

$$(-4)(-3)=12,\qquad(-12)\div3=-4$$

## Powers and Roots

In $a^n$, $a$ is the base and $n$ the exponent.

**Exponent laws** for nonzero bases:

$$a^ma^n=a^{m+n}$$
$$\frac{a^m}{a^n}=a^{m-n}$$
$$(a^m)^n=a^{mn}$$
$$(ab)^n=a^nb^n$$
$$a^0=1,\qquad a^{-n}=\frac1{a^n}$$

Example: $(2x^3)^2=4x^6$.

An $n$th root reverses an $n$th power:

$$\sqrt{49}=7,\qquad\sqrt[3]{-8}=-2$$

Remember: $\sqrt{49}$ means the principal root $7$, while solving $x^2=49$ gives $x=\pm7$.

## Scientific Notation

Write nonzero numbers as $a\times10^n$ where $1\le|a|<10$.

$$5{,}600{,}000=5.6\times10^6,\qquad0.00042=4.2\times10^{-4}$$

Multiply coefficients and add exponents:

$$(3\times10^4)(2\times10^{-7})=6\times10^{-3}$$

## Variables and Expressions

A variable represents a number. A term is a product of numbers and variables; like terms have identical variable parts.

$$3x+5x-2+7=8x+5$$

**Distribute and combine:**

$$4(2x-3)-x=8x-12-x=7x-12$$

**Evaluate:** If $x=-2$, then $3x^2-4=3(4)-4=8$.

## Equations

An equation says two expressions are equal. Perform the same valid operation on both sides.

$$3x+5=20$$
$$3x=15$$
$$x=5$$

Check: $3(5)+5=20$.

Equations may have:

- One solution: $2x=6\Rightarrow x=3$.
- No solution: $2x+1=2x+4\Rightarrow1=4$.
- Infinitely many solutions: $2(x+1)=2x+2$.

## Inequalities

Solve like equations, but reverse the inequality when multiplying or dividing by a negative number.

$$-3x+2>11\Rightarrow-3x>9\Rightarrow x<-3$$

**Interval notation:**

- $x<4$: $(-\infty,4)$.
- $x\ge-2$: $[-2,\infty)$.
- $-1<x\le3$: $(-1,3]$.

**Compound inequality:**

$$2<3x-1\le8\Rightarrow3<3x\le9\Rightarrow1<x\le3$$

## Absolute Value

$|x|$ is the distance from $x$ to $0$, so it is never negative.

$$|-7|=7,\qquad|3-8|=5$$

**Equations:** $|x|=a$ gives $x=\pm a$ when $a\ge0$.

$$|2x-1|=5\Rightarrow2x-1=5\text{ or }2x-1=-5\Rightarrow x=3\text{ or }-2$$

**Inequalities:**

- $|x|<a\Rightarrow-a<x<a$.
- $|x|>a\Rightarrow x<-a$ or $x>a$.

## Patterns and Sequences

A sequence is an ordered list.

**Arithmetic sequence:** Constant difference $d$.

$$a_n=a_1+(n-1)d$$

For $4,7,10,\ldots$, $a_{20}=4+19(3)=61$.

**Geometric sequence:** Constant ratio $r$.

$$a_n=a_1r^{n-1}$$

For $3,6,12,\ldots$, $a_8=3(2^7)=384$.

---

# Stage 3: Algebra

## Linear Equations

A linear equation has variables only to the first power.

$$5(2x-1)-3=4x+10$$
$$10x-8=4x+10$$
$$6x=18$$
$$x=3$$

**Literal equations:** Isolate the requested variable.

$$A=\frac12bh\quad\Rightarrow\quad h=\frac{2A}{b}$$

**Word problem:** A taxi costs $\$4$ plus $\$2$ per km. For a $\$24$ ride:

$$4+2d=24\Rightarrow d=10\text{ km}$$

## Lines and Slope

Slope measures vertical change per horizontal change:

$$m=\frac{y_2-y_1}{x_2-x_1}$$

Through $(2,3)$ and $(6,11)$: $m=(11-3)/(6-2)=2$.

**Slope-intercept form:** $y=mx+b$.

**Point-slope form:** $y-y_1=m(x-x_1)$.

Line with slope $2$ through $(2,3)$:

$$y-3=2(x-2)\Rightarrow y=2x-1$$

- Parallel lines have equal slopes.
- Perpendicular nonvertical lines have slopes whose product is $-1$.
- A vertical line $x=c$ has undefined slope.
- A horizontal line $y=c$ has slope $0$.

## Systems of Equations

A solution satisfies every equation.

**Substitution:**

$$y=2x+1,\qquad x+y=10$$
$$x+(2x+1)=10\Rightarrow x=3,\quad y=7$$

**Elimination:**

$$2x+y=9$$
$$3x-y=6$$
$$5x=15\Rightarrow x=3,\quad y=3$$

Geometrically, two lines may intersect once, never intersect, or be the same line.

## Polynomials

A polynomial is a sum of terms $ax^n$ with nonnegative integer exponents.

- Degree: largest exponent.
- Leading coefficient: coefficient of the highest-degree term.
- Constant: term without a variable.

**Add:** Combine like terms.

$$(3x^2+2x-1)+(x^2-5x+4)=4x^2-3x+3$$

**Multiply:**

$$(x+3)(x-2)=x^2+x-6$$

**Important products:**

$$(a+b)^2=a^2+2ab+b^2$$
$$(a-b)^2=a^2-2ab+b^2$$
$$(a+b)(a-b)=a^2-b^2$$

## Factoring

Factoring reverses multiplication.

**Greatest common factor:**

$$6x^3+9x^2=3x^2(2x+3)$$

**Difference of squares:**

$$x^2-25=(x-5)(x+5)$$

**Trinomial:**

$$x^2+7x+12=(x+3)(x+4)$$

**Grouping:**

$$x^3+2x^2+3x+6=x^2(x+2)+3(x+2)=(x+2)(x^2+3)$$

Always check whether the result expands back to the original.

## Quadratic Equations

A quadratic has form $ax^2+bx+c=0$, where $a\ne0$.

**Factoring:**

$$x^2-5x+6=0\Rightarrow(x-2)(x-3)=0\Rightarrow x=2,3$$

**Square-root method:**

$$(x-1)^2=9\Rightarrow x-1=\pm3\Rightarrow x=4,-2$$

**Quadratic formula:**

$$x=\frac{-b\pm\sqrt{b^2-4ac}}{2a}$$

For $2x^2+3x-2=0$:

$$x=\frac{-3\pm\sqrt{9+16}}4=\frac{-3\pm5}4=\frac12,-2$$

The discriminant $\Delta=b^2-4ac$ tells the number of real roots:

- $\Delta>0$: two distinct real roots.
- $\Delta=0$: one repeated real root.
- $\Delta<0$: two complex roots.

**Vertex:** For $y=ax^2+bx+c$, the axis is $x=-b/(2a)$.

## Rational Expressions

A rational expression is a fraction of polynomials. Values making the original denominator zero are excluded.

$$\frac{x^2-9}{x^2-x-6}
=\frac{(x-3)(x+3)}{(x-3)(x+2)}
=\frac{x+3}{x+2},\quad x\ne3,-2$$

**Divide rational expressions:** Multiply by the reciprocal.

$$\frac{x}{3}\div\frac{x^2}{6}=\frac{x}{3}\cdot\frac6{x^2}=\frac2x,\quad x\ne0$$

**Rational equation:** State restrictions, clear denominators, and check answers.

$$\frac1x+\frac12=1,\quad x\ne0$$
$$2+x=2x\Rightarrow x=2$$

## Radicals and Rational Exponents

$$a^{m/n}=\sqrt[n]{a^m}$$

Example: $27^{2/3}=(\sqrt[3]{27})^2=9$.

**Simplify:**

$$\sqrt{72}=\sqrt{36\cdot2}=6\sqrt2$$

**Combine only like radicals:** $3\sqrt2+5\sqrt2=8\sqrt2$.

**Rationalize a simple denominator:**

$$\frac3{\sqrt5}\cdot\frac{\sqrt5}{\sqrt5}=\frac{3\sqrt5}{5}$$

Squaring can introduce extraneous answers, so check radical equations in the original.

## Exponential and Logarithmic Equations

An exponential equation has the variable in an exponent.

$$2^{x+1}=16=2^4\Rightarrow x=3$$

A logarithm asks for an exponent:

$$\log_b a=c\quad\Longleftrightarrow\quad b^c=a$$

Thus $\log_2 8=3$.

**Log laws** for positive arguments:

$$\log_b(xy)=\log_bx+\log_by$$
$$\log_b(x/y)=\log_bx-\log_by$$
$$\log_b(x^p)=p\log_bx$$

**Change of base:**

$$\log_bx=\frac{\ln x}{\ln b}$$

Example:

$$3^x=10\Rightarrow x\ln3=\ln10\Rightarrow x=\frac{\ln10}{\ln3}\approx2.096$$

---

# Stage 4: Geometry

## Geometry Basics

- Point: exact location.
- Line: extends forever in two directions.
- Ray: starts at one point and extends forever.
- Segment: part of a line between two endpoints.
- Plane: flat two-dimensional surface.

Undefined sketches are not measurements. Markings and stated facts determine equality, parallelism, and right angles.

## Angles and Parallel Lines

- Acute: less than $90^\circ$.
- Right: $90^\circ$.
- Obtuse: between $90^\circ$ and $180^\circ$.
- Straight: $180^\circ$.
- Full turn: $360^\circ$.

Complementary angles sum to $90^\circ$; supplementary angles sum to $180^\circ$.

Vertical angles are equal. When a transversal crosses parallel lines, corresponding and alternate interior angles are equal; same-side interior angles are supplementary.

Example: If a corresponding angle is $68^\circ$, every matching acute angle is $68^\circ$ and each adjacent obtuse angle is $112^\circ$.

## Triangles

Triangle interior angles total $180^\circ$.

$$A+B+C=180^\circ$$

If $A=50^\circ$ and $B=65^\circ$, then $C=65^\circ$.

**By sides:** equilateral, isosceles, scalene.

**By angles:** acute, right, obtuse.

**Pythagorean theorem** for a right triangle:

$$a^2+b^2=c^2$$

Legs $6$ and $8$ give $c=\sqrt{36+64}=10$.

**Triangle inequality:** Each side must be shorter than the sum of the other two.

**Area:**

$$A=\frac12bh$$

## Congruence and Similarity

Congruent figures have the same shape and size. Common triangle tests:

- SSS: three matching sides.
- SAS: two sides and included angle.
- ASA/AAS: two angles and a side.
- HL: hypotenuse and a leg in right triangles.

AAA proves similarity, not congruence.

Similar figures have equal corresponding angles and proportional corresponding lengths.

Example: Scale factor $3$ multiplies lengths by $3$, areas by $3^2=9$, and volumes by $3^3=27$.

## Polygons

The sum of interior angles of an $n$-gon is:

$$S=(n-2)180^\circ$$

A hexagon has $(6-2)180^\circ=720^\circ$.

Each interior angle of a regular $n$-gon is $(n-2)180^\circ/n$. Exterior angles, one at each vertex, always total $360^\circ$.

**Common areas:**

| Shape | Area |
|---|---|
| Rectangle | $A=lw$ |
| Parallelogram | $A=bh$ |
| Triangle | $A=\frac12bh$ |
| Trapezoid | $A=\frac12(b_1+b_2)h$ |
| Regular polygon | $A=\frac12(\text{apothem})(\text{perimeter})$ |

## Circles

Radius $r$ runs from center to circle; diameter $d=2r$.

$$C=2\pi r,\qquad A=\pi r^2$$

For $r=4$, $C=8\pi$ and $A=16\pi$.

**Arc length** with central angle $\theta$ in degrees:

$$s=\frac{\theta}{360^\circ}2\pi r$$

**Sector area:**

$$A_{\text{sector}}=\frac{\theta}{360^\circ}\pi r^2$$

An inscribed angle measures half its intercepted arc.

## Coordinate Geometry

For points $(x_1,y_1)$ and $(x_2,y_2)$:

$$d=\sqrt{(x_2-x_1)^2+(y_2-y_1)^2}$$

$$M=\left(\frac{x_1+x_2}{2},\frac{y_1+y_2}{2}\right)$$

For $(1,2)$ and $(5,5)$:

$$d=\sqrt{4^2+3^2}=5,\qquad M=(3,3.5)$$

**Circle centered at $(h,k)$:**

$$(x-h)^2+(y-k)^2=r^2$$

## Transformations

- Translation by $\langle a,b\rangle$: $(x,y)\mapsto(x+a,y+b)$.
- Reflection across $x$-axis: $(x,y)\mapsto(x,-y)$.
- Reflection across $y$-axis: $(x,y)\mapsto(-x,y)$.
- $90^\circ$ counterclockwise rotation: $(x,y)\mapsto(-y,x)$.
- Dilation about origin by $k$: $(x,y)\mapsto(kx,ky)$.

Translations, rotations, and reflections preserve lengths and angles. Dilations preserve angles but scale lengths.

## Area, Surface Area, and Volume

| Solid | Volume | Surface Area |
|---|---|---|
| Rectangular prism | $V=lwh$ | $SA=2(lw+lh+wh)$ |
| Cylinder | $V=\pi r^2h$ | $SA=2\pi r^2+2\pi rh$ |
| Pyramid | $V=\frac13Bh$ | depends on faces |
| Cone | $V=\frac13\pi r^2h$ | $SA=\pi r^2+\pi r\ell$ |
| Sphere | $V=\frac43\pi r^3$ | $SA=4\pi r^2$ |

Example: A cylinder with $r=3$, $h=5$ has volume $45\pi$.

Use square units for area and cubic units for volume.

---

# Stage 5: Functions and Precalculus

## Functions

A function assigns exactly one output to each allowed input.

$$y=f(x)$$

If $f(x)=2x^2-3$, then $f(4)=2(16)-3=29$.

- **Domain:** allowed inputs.
- **Range:** resulting outputs.
- **Zero/root:** input where $f(x)=0$.
- **Intercepts:** $(x,0)$ and $(0,y)$ where the graph meets the axes.
- **Increasing/decreasing:** whether outputs rise/fall as inputs increase.

**Domain restrictions:**

- Denominator cannot be zero: $f(x)=1/(x-2)$ requires $x\ne2$.
- Even root needs a nonnegative radicand over the reals: $\sqrt{x+3}$ requires $x\ge-3$.
- Logarithm needs a positive argument: $\ln(x-1)$ requires $x>1$.

**Vertical-line test:** A graph represents a function if no vertical line crosses it more than once.

## Graph Transformations

Starting with $y=f(x)$:

| Transformation | New function |
|---|---|
| Up $k$ | $f(x)+k$ |
| Right $h$ | $f(x-h)$ |
| Vertical stretch by $a$ | $af(x)$ |
| Horizontal compression by $b$ | $f(bx)$ |
| Reflect across $x$-axis | $-f(x)$ |
| Reflect across $y$-axis | $f(-x)$ |

Example: $y=-2(x-3)^2+5$ is $y=x^2$ shifted right $3$, stretched vertically by $2$, reflected across the $x$-axis, and shifted up $5$.

Inside changes act horizontally and in the opposite direction.

## Linear and Quadratic Functions

**Linear:** $f(x)=mx+b$ has constant rate of change $m$.

Example: $C(t)=15t+40$ means an initial cost of $40$ and a cost increase of $15$ per unit of $t$.

**Quadratic forms:**

- Standard: $f(x)=ax^2+bx+c$.
- Vertex: $f(x)=a(x-h)^2+k$; vertex $(h,k)$.
- Factored: $f(x)=a(x-r_1)(x-r_2)$; roots $r_1,r_2$.

Example:

$$x^2-6x+5=(x-3)^2-4=(x-1)(x-5)$$

This shows vertex $(3,-4)$ and roots $1,5$.

## Polynomial and Rational Functions

A degree-$n$ polynomial has at most $n$ real roots and its end behavior is controlled by its leading term.

- Even degree, positive leading coefficient: both ends rise.
- Even degree, negative leading coefficient: both ends fall.
- Odd degree, positive leading coefficient: left falls, right rises.
- Odd degree, negative leading coefficient: left rises, right falls.

**Multiplicity:** A graph crosses at a root of odd multiplicity and touches/turns at a root of even multiplicity.

Example: $f(x)=(x-1)^2(x+2)$ touches at $x=1$ and crosses at $x=-2$.

A rational function $p(x)/q(x)$ may have:

- Vertical asymptotes where uncancelled denominator factors are zero.
- Holes where a common factor cancels.
- Horizontal asymptote found from leading degrees.

For $f(x)=(2x+1)/(x-3)$, $x=3$ is a vertical asymptote and $y=2$ is a horizontal asymptote.

## Exponential and Logarithmic Functions

**Exponential model:**

$$f(t)=Ab^t=Ae^{kt}$$

- $b>1$ or $k>0$: growth.
- $0<b<1$ or $k<0$: decay.

Population starting at $500$ and growing $4\%$ yearly:

$$P(t)=500(1.04)^t$$

**Doubling time:** For $Ae^{kt}$, $T_d=\ln2/k$.

**Half-life:** For $Ae^{-kt}$, $T_{1/2}=\ln2/k$.

The logarithm $y=\log_bx$ is the inverse of $y=b^x$.

$$b^{\log_bx}=x,\qquad\log_b(b^x)=x$$

Logs turn multiplication into addition, which makes them useful for scales, growth, and solving exponential equations.

## Piecewise, Composite, and Inverse Functions

A piecewise function uses different rules on different intervals:

$$f(x)=
\begin{cases}
x^2,&x<0\\
2x+1,&x\ge0
\end{cases}$$

Then $f(-2)=4$ and $f(3)=7$.

**Composition:**

$$(f\circ g)(x)=f(g(x))$$

If $f(x)=x^2$ and $g(x)=x+1$, then $(f\circ g)(x)=(x+1)^2$.

**Inverse function:** Reverses input and output.

For $f(x)=3x-5$:

$$y=3x-5\Rightarrow x=\frac{y+5}{3}\Rightarrow f^{-1}(x)=\frac{x+5}{3}$$

A function needs to be one-to-one on its domain to have a function inverse. Check with the horizontal-line test.

## Advanced Sequences and Series

A series is the sum of sequence terms.

**Arithmetic sum:**

$$S_n=\frac n2(a_1+a_n)=\frac n2[2a_1+(n-1)d]$$

For $2+5+\cdots+29$ with $10$ terms:

$$S_{10}=\frac{10}{2}(2+29)=155$$

**Finite geometric sum:**

$$S_n=a_1\frac{1-r^n}{1-r},\quad r\ne1$$

**Infinite geometric sum:** If $|r|<1$,

$$S_\infty=\frac{a_1}{1-r}$$

Thus $1+\frac12+\frac14+\cdots=2$.

Sigma notation compresses sums:

$$\sum_{k=1}^{4}k^2=1+4+9+16=30$$

---

# Stage 6: Trigonometry and Analytic Geometry

## Right-Triangle Trigonometry

For an acute angle $\theta$ in a right triangle:

$$\sin\theta=\frac{\text{opposite}}{\text{hypotenuse}}$$
$$\cos\theta=\frac{\text{adjacent}}{\text{hypotenuse}}$$
$$\tan\theta=\frac{\text{opposite}}{\text{adjacent}}$$

Mnemonic: SOH-CAH-TOA.

If opposite $=3$, adjacent $=4$, hypotenuse $=5$:

$$\sin\theta=\frac35,\quad\cos\theta=\frac45,\quad\tan\theta=\frac34$$

Use inverse trig to find angles:

$$\theta=\tan^{-1}(3/4)\approx36.87^\circ$$

Check whether the calculator is in degree or radian mode.

## Radians and the Unit Circle

Radians measure angle by arc length divided by radius:

$$\theta=\frac sr,\qquad180^\circ=\pi\text{ radians}$$

Conversions:

$$60^\circ\cdot\frac{\pi}{180^\circ}=\frac\pi3$$

On the unit circle, the point at angle $\theta$ is:

$$(\cos\theta,\sin\theta)$$

| $\theta$ | $\sin\theta$ | $\cos\theta$ | $\tan\theta$ |
|---|---:|---:|---:|
| $0$ | $0$ | $1$ | $0$ |
| $\pi/6$ | $1/2$ | $\sqrt3/2$ | $\sqrt3/3$ |
| $\pi/4$ | $\sqrt2/2$ | $\sqrt2/2$ | $1$ |
| $\pi/3$ | $\sqrt3/2$ | $1/2$ | $\sqrt3$ |
| $\pi/2$ | $1$ | $0$ | undefined |

Signs by quadrant: all positive in I; sine in II; tangent in III; cosine in IV.

## Trigonometric Graphs

For:

$$y=A\sin(B(x-C))+D$$

- Amplitude: $|A|$.
- Period: $2\pi/|B|$.
- Phase shift: $C$.
- Midline: $y=D$.

Example: $y=3\sin(2x)+1$ has amplitude $3$, period $\pi$, and midline $y=1$.

Cosine has the same period. Tangent has period $\pi/|B|$ and no amplitude.

## Identities and Equations

**Reciprocal and quotient identities:**

$$\sec x=\frac1{\cos x},\quad\csc x=\frac1{\sin x},\quad\cot x=\frac1{\tan x}$$

$$\tan x=\frac{\sin x}{\cos x}$$

**Pythagorean identities:**

$$\sin^2x+\cos^2x=1$$
$$1+\tan^2x=\sec^2x$$
$$1+\cot^2x=\csc^2x$$

**Angle addition:**

$$\sin(a+b)=\sin a\cos b+\cos a\sin b$$
$$\cos(a+b)=\cos a\cos b-\sin a\sin b$$

Example on $0\le x<2\pi$:

$$2\sin x=1\Rightarrow\sin x=\frac12\Rightarrow x=\frac\pi6,\frac{5\pi}6$$

When proving an identity, transform one side using known identities; do not treat it like an equation to solve.

## Laws of Sines and Cosines

For any triangle, with sides opposite their matching angles:

**Law of Sines:**

$$\frac a{\sin A}=\frac b{\sin B}=\frac c{\sin C}$$

Use it when an angle-side opposite pair is known. Be careful with the ambiguous SSA case.

**Law of Cosines:**

$$c^2=a^2+b^2-2ab\cos C$$

Use it for SSS or SAS data.

Example: $a=5$, $b=7$, $C=60^\circ$:

$$c^2=25+49-70(0.5)=39\Rightarrow c=\sqrt{39}$$

**Triangle area from two sides and included angle:**

$$A=\frac12ab\sin C$$

## Conic Sections

Conics arise by slicing a cone.

| Conic | Standard equation | Key feature |
|---|---|---|
| Circle | $(x-h)^2+(y-k)^2=r^2$ | equal distance from center |
| Parabola | $(x-h)^2=4p(y-k)$ | one focus and directrix |
| Ellipse | $\frac{(x-h)^2}{a^2}+\frac{(y-k)^2}{b^2}=1$ | sum of focal distances fixed |
| Hyperbola | $\frac{(x-h)^2}{a^2}-\frac{(y-k)^2}{b^2}=1$ | difference of focal distances fixed |

For $x^2/25+y^2/9=1$, the ellipse is centered at $(0,0)$ with semiaxes $5$ and $3$.

## Vectors

A vector has magnitude and direction.

$$\mathbf{v}=\langle v_1,v_2\rangle,\qquad\|\mathbf{v}\|=\sqrt{v_1^2+v_2^2}$$

For $\mathbf{v}=\langle3,4\rangle$, $\|\mathbf{v}\|=5$ and its unit vector is $\langle3/5,4/5\rangle$.

**Operations:**

$$\langle a,b\rangle+\langle c,d\rangle=\langle a+c,b+d\rangle$$

$$k\langle a,b\rangle=\langle ka,kb\rangle$$

**Dot product:**

$$\mathbf{u}\cdot\mathbf{v}=u_1v_1+u_2v_2=\|\mathbf{u}\|\|\mathbf{v}\|\cos\theta$$

Perpendicular nonzero vectors have dot product $0$.

Example: $\langle1,2\rangle\cdot\langle2,-1\rangle=2-2=0$.

## Complex Numbers

The imaginary unit satisfies $i^2=-1$. A complex number is $z=a+bi$.

$$i^0=1,\ i^1=i,\ i^2=-1,\ i^3=-i,\ i^4=1$$

**Multiply:**

$$(2+3i)(1-i)=2-2i+3i-3i^2=5+i$$

**Conjugate:** $\overline z=a-bi$.

$$(a+bi)(a-bi)=a^2+b^2$$

**Magnitude:**

$$|a+bi|=\sqrt{a^2+b^2}$$

**Polar form:**

$$z=r(\cos\theta+i\sin\theta)=re^{i\theta}$$

Multiplying complex numbers multiplies magnitudes and adds angles.

---

# Stage 7: Probability and Statistics

## Descriptive Statistics

For data $2,3,3,7,10$:

- Mean: $\bar x=(2+3+3+7+10)/5=5$.
- Median: middle value $=3$.
- Mode: most frequent value $=3$.
- Range: $10-2=8$.

**Population variance and standard deviation:**

$$\sigma^2=\frac1N\sum(x_i-\mu)^2,\qquad\sigma=\sqrt{\sigma^2}$$

For a sample, use $n-1$ in the denominator:

$$s^2=\frac1{n-1}\sum(x_i-\bar x)^2$$

Standard deviation measures typical spread around the mean. The interquartile range $IQR=Q_3-Q_1$ is more resistant to outliers.

Potential outliers lie below $Q_1-1.5IQR$ or above $Q_3+1.5IQR$.

## Counting Principles

**Product rule:** If one choice has $m$ options and the next has $n$, there are $mn$ outcomes.

Example: $3$ shirts and $4$ trousers make $12$ outfits.

**Factorial:** $n!=n(n-1)\cdots1$ and $0!=1$.

**Permutations:** Order matters.

$$P(n,r)=\frac{n!}{(n-r)!}$$

Arrange $3$ of $5$ books: $P(5,3)=5\cdot4\cdot3=60$.

**Combinations:** Order does not matter.

$$\binom nr=\frac{n!}{r!(n-r)!}$$

Choose $3$ of $5$ people: $\binom53=10$.

## Probability

For equally likely outcomes:

$$P(A)=\frac{\text{favorable outcomes}}{\text{total outcomes}}$$

Probability is between $0$ and $1$.

**Complement:**

$$P(A^c)=1-P(A)$$

**Addition rule:**

$$P(A\cup B)=P(A)+P(B)-P(A\cap B)$$

On a fair die, $A=$ even and $B=$ greater than $3$:

$$P(A\cup B)=\frac36+\frac36-\frac26=\frac46=\frac23$$

For independent events:

$$P(A\cap B)=P(A)P(B)$$

Two heads in two fair coin flips: $(1/2)^2=1/4$.

## Conditional Probability and Bayes' Theorem

Conditional probability updates after learning that $B$ occurred:

$$P(A\mid B)=\frac{P(A\cap B)}{P(B)}$$

$A$ and $B$ are independent exactly when $P(A\mid B)=P(A)$, assuming $P(B)>0$.

**Bayes' theorem:**

$$P(A\mid B)=\frac{P(B\mid A)P(A)}{P(B)}$$

Example: A condition affects $1\%$ of people. A test is $90\%$ sensitive and has a $5\%$ false-positive rate.

$$P(\text{condition}\mid+)=\frac{0.90(0.01)}{0.90(0.01)+0.05(0.99)}\approx15.4\%$$

A positive test is not the same as a $90\%$ chance of having the condition; the base rate matters.

## Random Variables and Distributions

A random variable assigns a number to each random outcome.

For a discrete random variable:

$$E[X]=\sum xP(X=x)$$

$$\operatorname{Var}(X)=E[X^2]-E[X]^2$$

Example: Fair die expectation:

$$E[X]=\frac{1+2+3+4+5+6}{6}=3.5$$

Expected value is a long-run average, not necessarily a possible single outcome.

For continuous variables, probabilities are areas under a density curve and $P(X=x)=0$ at any exact point.

## Normal and Binomial Distributions

**Binomial distribution:** Counts successes in $n$ independent trials with constant success probability $p$.

$$P(X=k)=\binom nkp^k(1-p)^{n-k}$$

$$E[X]=np,\qquad\operatorname{SD}(X)=\sqrt{np(1-p)}$$

For $n=5$, $p=0.2$, exactly two successes:

$$P(X=2)=\binom52(0.2)^2(0.8)^3=0.2048$$

**Normal distribution:** Bell-shaped and determined by mean $\mu$ and standard deviation $\sigma$.

Standardize with:

$$z=\frac{x-\mu}{\sigma}$$

If $\mu=70$, $\sigma=10$, then $x=85$ has $z=1.5$.

Roughly $68\%$, $95\%$, and $99.7\%$ of normal data lie within $1$, $2$, and $3$ standard deviations.

## Sampling and Confidence Intervals

A population is the full group; a sample is the observed subset. Random sampling helps reduce selection bias.

**Standard error of a sample mean:**

$$SE=\frac{s}{\sqrt n}$$

A large-sample approximate confidence interval is:

$$\bar x\pm z^*\frac{s}{\sqrt n}$$

Example: $\bar x=50$, $s=8$, $n=64$, with $z^*=1.96$:

$$50\pm1.96(1)=50\pm1.96$$

A $95\%$ confidence method captures the true parameter in about $95\%$ of repeated samples. It does not mean $95\%$ of individual data lie in the interval.

## Hypothesis Testing

1. State null hypothesis $H_0$ and alternative $H_a$.
2. Choose a test and significance level $\alpha$.
3. Calculate a test statistic and p-value.
4. Reject $H_0$ if $p\le\alpha$; otherwise fail to reject it.
5. Interpret in context.

The p-value is the probability, assuming $H_0$ is true, of data at least as extreme as observed. It is not the probability that $H_0$ is true.

- Type I error: reject a true $H_0$.
- Type II error: fail to reject a false $H_0$.
- Statistical significance does not guarantee practical importance.

## Correlation and Regression

Correlation $r$ measures the direction and strength of a linear relationship:

$$-1\le r\le1$$

- $r$ near $1$: strong positive linear association.
- $r$ near $-1$: strong negative linear association.
- $r$ near $0$: little linear association.

The least-squares regression line is:

$$\hat y=a+bx$$

- $b$: predicted change in $y$ for one-unit increase in $x$.
- Residual: $y-\hat y$.
- $R^2$: proportion of variation in $y$ explained by the linear model.

Correlation does not prove causation. Outliers, lurking variables, or reversed cause and effect may explain an association.

---

# Stage 8: Discrete Mathematics and Number Theory

## Sets

A set is an unordered collection of distinct objects.

$$A=\{1,2,3\},\qquad B=\{3,4\}$$

- Union: $A\cup B=\{1,2,3,4\}$.
- Intersection: $A\cap B=\{3\}$.
- Difference: $A\setminus B=\{1,2\}$.
- Complement: $A^c$ contains elements in the universal set but not $A$.
- Subset: $A\subseteq B$ means every element of $A$ is in $B$.
- Cardinality: $|A|$ is the number of elements.
- Power set: $\mathcal P(A)$ contains all subsets; if $|A|=n$, then $|\mathcal P(A)|=2^n$.
- Cartesian product: $A\times B=\{(a,b):a\in A,b\in B\}$.

**De Morgan's laws:**

$$(A\cup B)^c=A^c\cap B^c$$
$$(A\cap B)^c=A^c\cup B^c$$

## Logic

A proposition is a statement that is true or false.

| Symbol | Meaning |
|---|---|
| $\neg p$ | not $p$ |
| $p\land q$ | $p$ and $q$ |
| $p\lor q$ | $p$ or $q$ |
| $p\to q$ | if $p$, then $q$ |
| $p\leftrightarrow q$ | $p$ exactly when $q$ |

$p\to q$ is false only when $p$ is true and $q$ is false. It is equivalent to $\neg p\lor q$.

- Converse of $p\to q$: $q\to p$.
- Contrapositive: $\neg q\to\neg p$; logically equivalent to the original.
- Inverse: $\neg p\to\neg q$.

**Quantifiers:**

- $\forall x$: for every $x$.
- $\exists x$: there exists an $x$.

Negation switches the quantifier:

$$\neg(\forall x\,P(x))\equiv\exists x\,\neg P(x)$$

## Proof Methods

**Direct proof:** Start from assumptions and logically reach the conclusion.

Example: If $n=2k$ is even, then $n^2=4k^2=2(2k^2)$ is even.

**Contrapositive:** To prove $p\to q$, prove $\neg q\to\neg p$.

**Contradiction:** Assume the claim is false and derive an impossibility.

**Cases:** Split all possibilities and prove each.

**Counterexample:** One valid counterexample disproves a universal claim. The statement “all primes are odd” fails for $2$.

A pattern suggests a conjecture but does not prove it.

## Mathematical Induction

Induction proves a statement $P(n)$ for every integer from a starting value.

1. Base case: prove $P(1)$.
2. Inductive hypothesis: assume $P(k)$.
3. Inductive step: use that assumption to prove $P(k+1)$.

Example:

$$1+2+\cdots+n=\frac{n(n+1)}2$$

Base: $1=1(2)/2$.

Assume $1+\cdots+k=k(k+1)/2$. Then:

$$1+\cdots+k+(k+1)
=\frac{k(k+1)}2+(k+1)
=\frac{(k+1)(k+2)}2$$

So the formula holds for all positive integers.

## Relations and Graphs

A relation on a set is a set of ordered pairs.

- Reflexive: $aRa$.
- Symmetric: $aRb\Rightarrow bRa$.
- Antisymmetric: $aRb$ and $bRa\Rightarrow a=b$.
- Transitive: $aRb$ and $bRc\Rightarrow aRc$.

An equivalence relation is reflexive, symmetric, and transitive. It divides a set into equivalence classes.

A graph $G=(V,E)$ has vertices and edges.

- Degree: number of edges touching a vertex.
- Path: sequence of connected vertices.
- Cycle: path returning to its start.
- Connected: every pair of vertices has a path.
- Tree: connected graph with no cycles.

For an undirected graph:

$$\sum_{v\in V}\deg(v)=2|E|$$

A tree with $n$ vertices has exactly $n-1$ edges.

## Prime Numbers and Divisibility

For integers $a,b$, $a\mid b$ means $b=ak$ for some integer $k$.

Every integer greater than $1$ has a unique prime factorization apart from order.

**Euclidean algorithm:**

$$252=2(105)+42$$
$$105=2(42)+21$$
$$42=2(21)+0$$

Therefore $\gcd(252,105)=21$.

**Bézout's identity:** There exist integers $x,y$ such that:

$$ax+by=\gcd(a,b)$$

For positive integers:

$$\gcd(a,b)\operatorname{lcm}(a,b)=ab$$

## Modular Arithmetic

$$a\equiv b\pmod n$$

means $n$ divides $a-b$, or $a$ and $b$ have the same remainder when divided by $n$.

$$17\equiv5\pmod{12}$$

Arithmetic respects congruence:

$$a\equiv b,\ c\equiv d\pmod n\Rightarrow a+c\equiv b+d,\ ac\equiv bd\pmod n$$

Example:

$$7^{100}\pmod6$$

Since $7\equiv1\pmod6$, $7^{100}\equiv1$.

A number $a$ has a multiplicative inverse modulo $n$ exactly when $\gcd(a,n)=1$.

Example: $3^{-1}\equiv5\pmod7$ because $3\cdot5=15\equiv1\pmod7$.

Modular arithmetic powers clocks, checksums, hashing concepts, and public-key cryptography.

---

# Stage 9: Calculus

## Limits and Continuity

A limit describes the value a function approaches:

$$\lim_{x\to a}f(x)=L$$

It may exist even if $f(a)$ is missing or different.

**Direct substitution:** If the function is continuous at $a$, substitute.

$$\lim_{x\to2}(x^2+3)=7$$

**Factor a removable zero-over-zero form:**

$$\lim_{x\to2}\frac{x^2-4}{x-2}
=\lim_{x\to2}(x+2)=4$$

One-sided limits must agree for a two-sided limit to exist.

A function is continuous at $a$ when:

1. $f(a)$ exists.
2. $\lim_{x\to a}f(x)$ exists.
3. $\lim_{x\to a}f(x)=f(a)$.

Important limit:

$$\lim_{x\to0}\frac{\sin x}{x}=1$$

## Derivatives

The derivative is instantaneous rate of change and tangent-line slope:

$$f'(x)=\lim_{h\to0}\frac{f(x+h)-f(x)}h$$

**Core rules:**

| Function | Derivative |
|---|---|
| $c$ | $0$ |
| $x^n$ | $nx^{n-1}$ |
| $e^x$ | $e^x$ |
| $a^x$ | $a^x\ln a$ |
| $\ln x$ | $1/x$ |
| $\sin x$ | $\cos x$ |
| $\cos x$ | $-\sin x$ |
| $\tan x$ | $\sec^2x$ |

**Linearity:**

$$(af+bg)'=af'+bg'$$

**Product rule:**

$$(fg)'=f'g+fg'$$

**Quotient rule:**

$$\left(\frac fg\right)'=\frac{f'g-fg'}{g^2}$$

**Chain rule:**

$$\frac d{dx}f(g(x))=f'(g(x))g'(x)$$

Example:

$$\frac d{dx}(3x^2+1)^5=5(3x^2+1)^4(6x)$$

**Implicit differentiation:** For $x^2+y^2=25$:

$$2x+2y\frac{dy}{dx}=0\Rightarrow\frac{dy}{dx}=-\frac xy$$

## Applications of Derivatives

**Tangent line at $x=a$:**

$$y-f(a)=f'(a)(x-a)$$

For $f(x)=x^2$ at $x=2$, slope is $4$:

$$y-4=4(x-2)\Rightarrow y=4x-4$$

**Motion:**

$$v(t)=s'(t),\qquad a(t)=v'(t)=s''(t)$$

**Critical points:** Values where $f'(x)=0$ or $f'$ does not exist. Test them and endpoints for extrema.

- $f'>0$: function increasing.
- $f'<0$: function decreasing.
- $f''>0$: concave up.
- $f''<0$: concave down.

**Optimization example:** A rectangle has perimeter $20$. If sides are $x$ and $10-x$:

$$A(x)=x(10-x)=10x-x^2$$
$$A'(x)=10-2x=0\Rightarrow x=5$$

The maximum-area rectangle is a $5\times5$ square.

**Linear approximation:**

$$f(x)\approx f(a)+f'(a)(x-a)$$

Since $\sqrt{100}=10$ and $f'(100)=1/20$, $\sqrt{101}\approx10.05$.

## Integrals

An antiderivative reverses differentiation:

$$\int f(x)\,dx=F(x)+C\quad\text{when }F'(x)=f(x)$$

**Core rules:**

$$\int x^n\,dx=\frac{x^{n+1}}{n+1}+C,\quad n\ne-1$$

$$\int\frac1x\,dx=\ln|x|+C$$

$$\int e^x\,dx=e^x+C$$

$$\int\cos x\,dx=\sin x+C$$

$$\int\sin x\,dx=-\cos x+C$$

**Definite integral:** Signed area and accumulated change.

$$\int_a^bf(x)\,dx$$

**Fundamental Theorem of Calculus:**

$$\int_a^bf(x)\,dx=F(b)-F(a)$$

Example:

$$\int_0^2 3x^2\,dx=[x^3]_0^2=8$$

The constant $C$ is needed for indefinite integrals because all constants differentiate to zero.

## Applications of Integrals

**Area between curves:**

$$A=\int_a^b(\text{top}-\text{bottom})\,dx$$

Between $y=x$ and $y=x^2$ on $[0,1]$:

$$A=\int_0^1(x-x^2)\,dx=\frac12-\frac13=\frac16$$

**Average value:**

$$f_{\text{avg}}=\frac1{b-a}\int_a^bf(x)\,dx$$

**Volume by disks/washers:**

$$V=\pi\int_a^b(R^2-r^2)\,dx$$

**Volume by cylindrical shells:**

$$V=2\pi\int_a^b(\text{radius})(\text{height})\,dx$$

**Total distance:** Integrate speed $|v(t)|$, not velocity.

## Integration Techniques

**Substitution** reverses the chain rule.

$$\int2x\cos(x^2)\,dx$$

Let $u=x^2$, $du=2x\,dx$:

$$\int\cos u\,du=\sin u+C=\sin(x^2)+C$$

**Integration by parts:**

$$\int u\,dv=uv-\int v\,du$$

Example:

$$\int xe^x\,dx=xe^x-\int e^x\,dx=e^x(x-1)+C$$

Other useful methods include partial fractions for rational functions, trigonometric identities, and improper integrals evaluated as limits.

## Differential Equations

A differential equation relates a function to its derivatives.

**Exponential growth/decay:**

$$\frac{dy}{dt}=ky\Rightarrow y=Ce^{kt}$$

If $y(0)=5$, then $C=5$.

**Separable equation:**

$$\frac{dy}{dx}=xy$$
$$\frac1y\,dy=x\,dx$$
$$\ln|y|=\frac{x^2}{2}+C$$
$$y=Ce^{x^2/2}$$

An initial condition selects one solution from a family.

**First-order linear form:**

$$y'+P(x)y=Q(x)$$

An integrating factor is $\mu(x)=e^{\int P(x)\,dx}$.

## Infinite Series

An infinite series converges when its partial sums approach a finite limit.

**Necessary condition:** If $\sum a_n$ converges, then $a_n\to0$. The converse is false; $\sum1/n$ diverges.

Common tests:

- Geometric: $\sum ar^n$ converges when $|r|<1$.
- $p$-series: $\sum1/n^p$ converges when $p>1$.
- Comparison test: compare positive terms with a known series.
- Ratio test: useful with factorials and exponentials.
- Alternating-series test: decreasing magnitudes approaching zero.

**Power series:**

$$\sum_{n=0}^{\infty}c_n(x-a)^n$$

**Maclaurin series:**

$$e^x=1+x+\frac{x^2}{2!}+\frac{x^3}{3!}+\cdots$$

$$\sin x=x-\frac{x^3}{3!}+\frac{x^5}{5!}-\cdots$$

Near $0$, $e^{0.1}\approx1+0.1+0.1^2/2=1.105$.

## Multivariable Calculus

A multivariable function has several inputs: $z=f(x,y)$.

**Partial derivatives:** Differentiate with respect to one variable while holding the others constant.

For $f(x,y)=x^2y+3y$:

$$f_x=2xy,\qquad f_y=x^2+3$$

**Gradient:**

$$\nabla f=\langle f_x,f_y\rangle$$

It points in the direction of steepest increase.

**Directional derivative** for unit vector $\mathbf u$:

$$D_{\mathbf u}f=\nabla f\cdot\mathbf u$$

**Double integral:**

$$\iint_Rf(x,y)\,dA$$

It accumulates over a region, such as volume beneath a surface.

**Critical points:** Solve $f_x=f_y=0$ and classify using context or the Hessian/second-derivative test.

---

# Stage 10: Linear Algebra and Applied Mathematics

## Matrices

A matrix is a rectangular array. An $m\times n$ matrix has $m$ rows and $n$ columns.

$$A=\begin{bmatrix}1&2\\3&4\end{bmatrix}$$

**Addition and scalar multiplication** act entry by entry.

**Matrix multiplication:** If $A$ is $m\times n$ and $B$ is $n\times p$, then $AB$ is $m\times p$.

$$
\begin{bmatrix}1&2\\3&4\end{bmatrix}
\begin{bmatrix}5\\6\end{bmatrix}
=
\begin{bmatrix}17\\39\end{bmatrix}
$$

In general, $AB\ne BA$.

**Transpose:** $A^T$ swaps rows and columns.

The identity matrix $I$ satisfies $AI=IA=A$.

## Linear Systems and Row Reduction

Represent a system with an augmented matrix:

$$
\begin{aligned}
x+2y&=5\\
3x+4y&=11
\end{aligned}
\quad\longrightarrow\quad
\left[\begin{array}{cc|c}
1&2&5\\
3&4&11
\end{array}\right]
$$

Replace row $2$ by $R_2-3R_1$:

$$
\left[\begin{array}{cc|c}
1&2&5\\
0&-2&-4
\end{array}\right]
$$

Thus $y=2$ and $x=1$.

Valid row operations:

- Swap two rows.
- Multiply a row by a nonzero constant.
- Add a multiple of one row to another.

Possible outcomes are one solution, infinitely many solutions, or no solution.

## Determinants and Inverses

For:

$$A=\begin{bmatrix}a&b\\c&d\end{bmatrix}$$

the determinant is:

$$\det(A)=ad-bc$$

The matrix is invertible exactly when $\det(A)\ne0$.

$$A^{-1}=\frac1{ad-bc}\begin{bmatrix}d&-b\\-c&a\end{bmatrix}$$

Example:

$$
A=\begin{bmatrix}2&1\\1&1\end{bmatrix},
\quad\det(A)=1,
\quad A^{-1}=\begin{bmatrix}1&-1\\-1&2\end{bmatrix}
$$

If $A\mathbf x=\mathbf b$ and $A$ is invertible, then $\mathbf x=A^{-1}\mathbf b$.

Geometrically, $|\det A|$ is the area/volume scaling factor of the linear transformation; a zero determinant collapses a dimension.

## Vector Spaces

A vector space is a set closed under vector addition and scalar multiplication and satisfying the standard algebraic rules.

- **Span:** all linear combinations of given vectors.
- **Linear independence:** no vector is redundant.
- **Basis:** linearly independent vectors that span the space.
- **Dimension:** number of vectors in a basis.
- **Column space:** span of a matrix's columns.
- **Null space:** solutions of $A\mathbf x=\mathbf0$.
- **Rank:** dimension of the column space.

In $\mathbb R^2$, $\langle1,0\rangle$ and $\langle0,1\rangle$ form the standard basis.

The vectors $\langle1,2\rangle$ and $\langle2,4\rangle$ are dependent because the second is twice the first.

**Projection of $\mathbf v$ onto nonzero $\mathbf u$:**

$$\operatorname{proj}_{\mathbf u}\mathbf v
=\frac{\mathbf v\cdot\mathbf u}{\mathbf u\cdot\mathbf u}\mathbf u$$

## Eigenvalues and Eigenvectors

An eigenvector keeps its direction under a linear transformation:

$$A\mathbf v=\lambda\mathbf v,\qquad\mathbf v\ne\mathbf0$$

Find eigenvalues from:

$$\det(A-\lambda I)=0$$

For:

$$A=\begin{bmatrix}2&0\\0&3\end{bmatrix}$$

the eigenvalues are $2$ and $3$, with eigenvectors along the $x$- and $y$-axes.

If enough independent eigenvectors exist:

$$A=PDP^{-1}$$

Then powers become easier:

$$A^n=PD^nP^{-1}$$

Eigenvalues appear in stability, vibration, data compression, Markov chains, and principal component analysis.

## Optimization

Optimization chooses the best feasible value of an objective.

**One variable:** Find critical points and endpoints.

**Several variables without constraints:** Solve $\nabla f=\mathbf0$ and classify candidates.

**Lagrange multipliers** for constraint $g(x,y)=c$:

$$\nabla f=\lambda\nabla g$$

Example: Maximize $f(x,y)=xy$ subject to $x+y=10$. Symmetry or Lagrange multipliers gives $x=y=5$, maximum product $25$.

**Linear programming:** Optimize a linear objective under linear constraints. In two dimensions, if an optimum exists, it occurs at a feasible-region vertex.

Always interpret domain constraints: negative time, length, or probability may be algebraically valid but physically meaningless.

## Numerical Methods and Error

Some problems have no convenient exact solution, so use controlled approximation.

**Bisection method:** If continuous $f$ changes sign across $[a,b]$, repeatedly halve the interval containing a root. It is slow but reliable.

**Newton's method:**

$$x_{n+1}=x_n-\frac{f(x_n)}{f'(x_n)}$$

For $x^2-2=0$, start $x_0=1.5$:

$$x_1=1.5-\frac{1.5^2-2}{2(1.5)}\approx1.4167$$

**Absolute error:**

$$|x_{\text{approx}}-x_{\text{exact}}|$$

**Relative error:**

$$\frac{|x_{\text{approx}}-x_{\text{exact}}|}{|x_{\text{exact}}|}$$

Avoid rounding too early. Keep extra digits during work and round once at the end.

## Problem-Solving Strategy

1. **Understand:** Identify what is known, unknown, and requested.
2. **Represent:** Draw a diagram, define variables, add units, or make a table.
3. **Choose:** Match the structure to a formula or method.
4. **Solve:** Work one justified step at a time.
5. **Check:** Substitute back, estimate size, test signs, and verify units.
6. **Interpret:** State the answer in the original context.

**Fast reasonableness checks:**

- A probability must lie between $0$ and $1$.
- A percentage increase should make a positive amount larger.
- Squared units belong to area; cubic units belong to volume.
- A square root chosen as a physical length is usually nonnegative.
- Correlation alone cannot establish cause.
- A derivative carries output units per input unit.
- A definite integral carries output units times input units.

**When stuck:**

- Try a smaller or simpler case.
- Rewrite using definitions.
- Factor, draw, tabulate, or graph.
- Work backward from the goal.
- Estimate before calculating.
- Separate exact work from decimal approximation.

## Essential Formula Sheet

### Arithmetic and Algebra

$$\%\text{ change}=\frac{\text{new}-\text{old}}{\text{old}}\cdot100\%$$

$$A=P(1+r)^t$$

$$a^ma^n=a^{m+n},\quad(a^m)^n=a^{mn},\quad a^{-n}=1/a^n$$

$$x=\frac{-b\pm\sqrt{b^2-4ac}}{2a}$$

$$a^2-b^2=(a-b)(a+b)$$

### Geometry and Trigonometry

$$a^2+b^2=c^2$$

$$C=2\pi r,\quad A_{\text{circle}}=\pi r^2$$

$$V_{\text{prism}}=Bh,\quad V_{\text{pyramid}}=\frac13Bh$$

$$\sin\theta=\frac{\text{opp}}{\text{hyp}},\quad
\cos\theta=\frac{\text{adj}}{\text{hyp}},\quad
\tan\theta=\frac{\text{opp}}{\text{adj}}$$

$$\sin^2x+\cos^2x=1$$

$$c^2=a^2+b^2-2ab\cos C$$

### Sequences, Probability, and Statistics

$$a_n=a_1+(n-1)d,\quad a_n=a_1r^{n-1}$$

$$S_{\text{arith}}=\frac n2(a_1+a_n),\quad
S_{\text{geom}}=a_1\frac{1-r^n}{1-r}$$

$$P(A\mid B)=\frac{P(A\cap B)}{P(B)}$$

$$\binom nr=\frac{n!}{r!(n-r)!}$$

$$z=\frac{x-\mu}{\sigma}$$

### Calculus and Linear Algebra

$$f'(x)=\lim_{h\to0}\frac{f(x+h)-f(x)}h$$

$$(fg)'=f'g+fg',\qquad(f\circ g)'=f'(g)g'$$

$$\int_a^bf(x)\,dx=F(b)-F(a)$$

$$\nabla f=\langle f_x,f_y,\ldots\rangle$$

$$\det\begin{bmatrix}a&b\\c&d\end{bmatrix}=ad-bc$$

$$A\mathbf v=\lambda\mathbf v$$

## Practice Problems

Try these without looking at the answers.

1. Find $35\%$ of $240$.
2. A price rises from $\$50$ to $\$62$. Find the percentage increase.
3. Simplify $\frac34+\frac56$.
4. Solve $5x-7=18$.
5. Solve $|2x+1|=7$.
6. Factor $x^2-x-12$.
7. Solve $x^2+2x-8=0$.
8. Find the slope through $(-1,2)$ and $(3,10)$.
9. A right triangle has legs $9$ and $12$. Find its hypotenuse.
10. Find the area of a circle with radius $5$.
11. Evaluate $f(-2)$ for $f(x)=x^3-2x$.
12. Solve $2^x=32$.
13. Find $\sin(\pi/6)$.
14. Find the tenth term of $4,7,10,\ldots$.
15. What is the probability of at least one head in two fair flips?
16. Compute $\binom{8}{2}$.
17. Find $\gcd(84,30)$.
18. Evaluate $38\bmod7$.
19. Differentiate $x^3e^x$.
20. Evaluate $\int_0^3 2x\,dx$.
21. Find $\nabla f$ for $f(x,y)=x^2+xy+y^2$.
22. Find the determinant of $\begin{bmatrix}4&2\\1&3\end{bmatrix}$.

**Answers:**

1. $84$.
2. $24\%$.
3. $19/12$.
4. $x=5$.
5. $x=3$ or $x=-4$.
6. $(x-4)(x+3)$.
7. $x=2,-4$.
8. $m=2$.
9. $15$.
10. $25\pi$.
11. $-4$.
12. $x=5$.
13. $1/2$.
14. $31$.
15. $3/4$.
16. $28$.
17. $6$.
18. $3$.
19. $e^x(x^3+3x^2)$.
20. $9$.
21. $\nabla f=\langle2x+y,x+2y\rangle$.
22. $10$.