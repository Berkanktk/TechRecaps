# CSS Learning Guide

## Table of Contents

1. [CSS Basics](#css-basics)
   1. [What is CSS](#what-is-css)
   2. [CSS Syntax](#css-syntax)
   3. [Selectors](#selectors)
   4. [Properties and Values](#properties-and-values)
2. [Adding CSS](#adding-css)
   1. [Inline CSS](#inline-css)
   2. [Internal CSS](#internal-css)
   3. [External CSS](#external-css)
   4. [CSS Specificity](#css-specificity)
3. [Text and Fonts](#text-and-fonts)
   1. [Text Properties](#text-properties)
   2. [Font Properties](#font-properties)
   3. [Text Effects](#text-effects)
4. [Colors and Backgrounds](#colors-and-backgrounds)
   1. [Color Values](#color-values)
   2. [Background Properties](#background-properties)
   3. [Gradients](#gradients)
5. [Box Model](#box-model)
   1. [Understanding Box Model](#understanding-box-model)
   2. [Margin and Padding](#margin-and-padding)
   3. [Border Properties](#border-properties)
   4. [Box Sizing](#box-sizing)
6. [Layout](#layout)
   1. [Display Property](#display-property)
   2. [Position Property](#position-property)
   3. [Float and Clear](#float-and-clear)
   4. [Overflow](#overflow)
7. [Flexbox](#flexbox)
   1. [Flex Container](#flex-container)
   2. [Flex Items](#flex-items)
   3. [Flex Direction and Wrap](#flex-direction-and-wrap)
   4. [Alignment Properties](#alignment-properties)
8. [CSS Grid](#css-grid)
   1. [Grid Container](#grid-container)
   2. [Grid Items](#grid-items)
   3. [Grid Areas](#grid-areas)
   4. [Grid Functions](#grid-functions)
9. [Responsive Design](#responsive-design)
   1. [Media Queries](#media-queries)
   2. [Responsive Units](#responsive-units)
   3. [Viewport Meta Tag](#viewport-meta-tag)
   4. [Mobile First Design](#mobile-first-design)
10. [Transformations and Animations](#transformations-and-animations)
    1. [2D Transforms](#2d-transforms)
    2. [3D Transforms](#3d-transforms)
    3. [Transitions](#transitions)
    4. [Animations](#animations)
11. [Advanced Selectors](#advanced-selectors)
    1. [Pseudo Classes](#pseudo-classes)
    2. [Pseudo Elements](#pseudo-elements)
    3. [Attribute Selectors](#attribute-selectors)
    4. [Combinators](#combinators)
12. [Modern CSS](#modern-css)
    1. [CSS Variables](#css-variables)
    2. [CSS Functions](#css-functions)
    3. [CSS Grid Advanced](#css-grid-advanced)
    4. [Container Queries](#container-queries)

---

## CSS Basics

### What is CSS

**CSS (Cascading Style Sheets)** controls the presentation of HTML elements.

**Key Benefits:**
- Separates content from presentation
- Reusable styles across pages
- Consistent design
- Responsive layouts

**How CSS Works:**
- Selects HTML elements
- Applies styling rules
- Cascades from general to specific

### CSS Syntax

```css
selector {
    property: value;
    property: value;
}

/* Comment */
h1 {
    color: blue;
    font-size: 24px;
}
```

**Parts:**
- **Selector**: Target element
- **Property**: Style attribute
- **Value**: Property setting
- **Declaration**: property-value pair

### Selectors

```css
/* Element selector */
p { color: black; }

/* Class selector */
.highlight { background: yellow; }

/* ID selector */
#header { font-size: 32px; }

/* Universal selector */
* { margin: 0; }

/* Multiple selectors */
h1, h2, h3 { font-weight: bold; }
```

### Properties and Values

```css
.text {
    color: red;              /* Color */
    font-size: 16px;         /* Size */
    margin: 10px;            /* Spacing */
    background: white;       /* Background */
    border: 1px solid black; /* Border */
}
```

---

## Adding CSS

### Inline CSS

```html
<p style="color: red; font-size: 18px;">Styled text</p>
<div style="background: blue; padding: 20px;">Box</div>
```

**Use:** Quick testing, specific elements

### Internal CSS

```html
<head>
    <style>
        body { font-family: Arial; }
        .container { max-width: 1200px; }
        #nav { background: #333; }
    </style>
</head>
```

**Use:** Single page styles

### External CSS

```html
<!-- HTML -->
<link rel="stylesheet" href="styles.css">
```

```css
/* styles.css */
body {
    font-family: Arial, sans-serif;
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
}
```

**Use:** Multiple pages, best practice

### CSS Specificity

```css
/* Specificity: 1 */
p { color: black; }

/* Specificity: 10 */
.text { color: blue; }

/* Specificity: 100 */
#heading { color: red; }

/* Specificity: 1000 */
<p style="color: green;">Text</p>

/* Override */
p { color: yellow !important; }
```

**Order:** inline > IDs > classes > elements

---

## Text and Fonts

### Text Properties

```css
.text {
    color: #333;
    text-align: center;      /* left, right, center, justify */
    text-decoration: underline; /* none, underline, line-through */
    text-transform: uppercase;  /* lowercase, capitalize */
    line-height: 1.5;
    letter-spacing: 2px;
    word-spacing: 5px;
    text-indent: 50px;
}
```

### Font Properties

```css
.font-styles {
    font-family: 'Arial', sans-serif;
    font-size: 18px;         /* px, em, rem, % */
    font-weight: bold;       /* normal, bold, 100-900 */
    font-style: italic;      /* normal, italic, oblique */
    font-variant: small-caps;
}

/* Web fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');

.custom-font {
    font-family: 'Roboto', sans-serif;
}
```

### Text Effects

```css
.text-effects {
    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    white-space: nowrap;     /* normal, nowrap, pre */
    overflow: hidden;
    text-overflow: ellipsis;

    /* Multi-line ellipsis */
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
}
```

---

## Colors and Backgrounds

### Color Values

```css
.colors {
    /* Named colors */
    color: red;

    /* Hex colors */
    color: #ff0000;
    color: #f00;

    /* RGB */
    color: rgb(255, 0, 0);
    color: rgba(255, 0, 0, 0.5);

    /* HSL */
    color: hsl(0, 100%, 50%);
    color: hsla(0, 100%, 50%, 0.5);
}
```

### Background Properties

```css
.background {
    background-color: #f0f0f0;
    background-image: url('image.jpg');
    background-repeat: no-repeat;    /* repeat, repeat-x, repeat-y */
    background-position: center top; /* keywords, %, px */
    background-size: cover;          /* contain, cover, px, % */
    background-attachment: fixed;    /* scroll, fixed */

    /* Shorthand */
    background: #fff url('bg.jpg') no-repeat center/cover;
}
```

### Gradients

```css
.gradients {
    /* Linear gradient */
    background: linear-gradient(to right, red, blue);
    background: linear-gradient(45deg, #ff0000, #0000ff);
    background: linear-gradient(to bottom, red 0%, blue 100%);

    /* Radial gradient */
    background: radial-gradient(circle, red, blue);
    background: radial-gradient(ellipse at center, red 0%, blue 100%);

    /* Multiple gradients */
    background:
        linear-gradient(45deg, transparent 30%, rgba(255,255,255,0.5) 30%),
        linear-gradient(-45deg, transparent 30%, rgba(0,0,0,0.1) 30%),
        linear-gradient(90deg, #ff0000, #0000ff);
}
```

---

## Box Model

### Understanding Box Model

```css
.box {
    width: 200px;
    height: 100px;
    padding: 20px;
    border: 5px solid black;
    margin: 10px;
}

/* Total width = 200 + 20*2 + 5*2 + 10*2 = 270px */
/* Total height = 100 + 20*2 + 5*2 + 10*2 = 170px */
```

### Margin and Padding

```css
.spacing {
    /* All sides */
    margin: 20px;
    padding: 15px;

    /* Vertical and horizontal */
    margin: 20px 10px;
    padding: 15px 25px;

    /* Top, horizontal, bottom */
    margin: 20px 10px 30px;

    /* Individual sides */
    margin: 20px 15px 10px 5px; /* top right bottom left */

    /* Specific sides */
    margin-top: 20px;
    margin-right: 15px;
    margin-bottom: 10px;
    margin-left: 5px;

    /* Auto centering */
    margin: 0 auto;
}
```

### Border Properties

```css
.borders {
    /* Basic border */
    border: 2px solid red;

    /* Individual properties */
    border-width: 2px;
    border-style: solid;     /* dotted, dashed, double, groove */
    border-color: red;

    /* Individual sides */
    border-top: 1px solid black;
    border-right: 2px dashed blue;
    border-bottom: 3px dotted green;
    border-left: 4px double red;

    /* Rounded corners */
    border-radius: 10px;
    border-radius: 10px 20px;
    border-radius: 10px 20px 30px 40px;

    /* Complex shapes */
    border-radius: 50%;      /* Circle */
    border-radius: 10px 10px 0 0; /* Top rounded */
}
```

### Box Sizing

```css
/* Default box model */
.content-box {
    box-sizing: content-box;
    width: 200px;
    padding: 20px;
    border: 5px solid black;
    /* Total width: 200 + 20*2 + 5*2 = 250px */
}

/* Border box model */
.border-box {
    box-sizing: border-box;
    width: 200px;
    padding: 20px;
    border: 5px solid black;
    /* Total width: 200px (includes padding and border) */
}

/* Apply to all elements */
* {
    box-sizing: border-box;
}
```

---

## Layout

### Display Property

```css
.display-types {
    display: block;          /* Full width, new line */
    display: inline;         /* Content width, same line */
    display: inline-block;   /* Content width, allows width/height */
    display: none;           /* Hidden, no space */
    display: flex;           /* Flexible layout */
    display: grid;           /* Grid layout */
}

.visibility {
    visibility: hidden;      /* Hidden, keeps space */
    visibility: visible;
}
```

### Position Property

```css
.positioning {
    position: static;        /* Default, normal flow */
    position: relative;      /* Relative to normal position */
    position: absolute;      /* Relative to positioned parent */
    position: fixed;         /* Relative to viewport */
    position: sticky;        /* Sticky positioning */

    top: 10px;
    right: 20px;
    bottom: 30px;
    left: 40px;
    z-index: 999;
}

.examples {
    /* Centered absolute */
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);

    /* Sticky header */
    position: sticky;
    top: 0;
    background: white;
    z-index: 100;
}
```

### Float and Clear

```css
.float-layout {
    float: left;             /* left, right, none */
    width: 30%;
}

.clear-float {
    clear: both;             /* left, right, both, none */
}

/* Clearfix */
.clearfix::after {
    content: "";
    display: table;
    clear: both;
}
```

### Overflow

```css
.overflow {
    overflow: visible;       /* Default */
    overflow: hidden;        /* Hide overflow */
    overflow: scroll;        /* Always scrollbars */
    overflow: auto;          /* Scrollbars when needed */

    overflow-x: hidden;
    overflow-y: scroll;
}
```

---

## Flexbox

### Flex Container

```css
.flex-container {
    display: flex;

    flex-direction: row;     /* row, column, row-reverse, column-reverse */
    flex-wrap: wrap;         /* nowrap, wrap, wrap-reverse */

    /* Shorthand */
    flex-flow: row wrap;

    justify-content: center; /* flex-start, flex-end, center, space-between, space-around, space-evenly */
    align-items: center;     /* flex-start, flex-end, center, baseline, stretch */
    align-content: center;   /* flex-start, flex-end, center, space-between, space-around, stretch */

    gap: 20px;               /* Space between items */
    row-gap: 20px;
    column-gap: 10px;
}
```

### Flex Items

```css
.flex-item {
    flex-grow: 1;            /* Growth factor */
    flex-shrink: 1;          /* Shrink factor */
    flex-basis: 200px;       /* Initial size */

    /* Shorthand */
    flex: 1;                 /* flex: 1 1 0% */
    flex: 200px;             /* flex: 1 1 200px */
    flex: 0 0 200px;         /* Don't grow/shrink, fixed 200px */

    align-self: flex-end;    /* Override align-items */
    order: 2;                /* Change visual order */
}
```

### Flex Direction and Wrap

```css
.flex-examples {
    /* Horizontal layout */
    display: flex;
    flex-direction: row;

    /* Vertical layout */
    display: flex;
    flex-direction: column;

    /* Wrap items */
    display: flex;
    flex-wrap: wrap;

    /* Reverse order */
    display: flex;
    flex-direction: row-reverse;
}
```

### Alignment Properties

```css
.flex-alignment {
    /* Center everything */
    display: flex;
    justify-content: center;
    align-items: center;

    /* Space between items */
    display: flex;
    justify-content: space-between;

    /* Stretch items */
    display: flex;
    align-items: stretch;

    /* Multiple lines */
    display: flex;
    flex-wrap: wrap;
    align-content: space-around;
}
```

---

## CSS Grid

### Grid Container

```css
.grid-container {
    display: grid;

    grid-template-columns: 200px 200px 200px;
    grid-template-columns: 1fr 1fr 1fr;        /* Fractional units */
    grid-template-columns: repeat(3, 1fr);     /* Repeat function */
    grid-template-columns: 200px 1fr 100px;    /* Mixed units */

    grid-template-rows: 100px 200px;
    grid-template-rows: repeat(2, 150px);

    gap: 20px;
    row-gap: 20px;
    column-gap: 10px;

    /* Alignment */
    justify-items: center;   /* start, end, center, stretch */
    align-items: center;     /* start, end, center, stretch */
    justify-content: center; /* start, end, center, stretch, space-around, space-between, space-evenly */
    align-content: center;
}
```

### Grid Items

```css
.grid-item {
    /* Grid positioning */
    grid-column: 1 / 3;      /* Start at line 1, end before line 3 */
    grid-row: 1 / 2;

    /* Alternative syntax */
    grid-column-start: 1;
    grid-column-end: 3;
    grid-row-start: 1;
    grid-row-end: 2;

    /* Span syntax */
    grid-column: span 2;     /* Span 2 columns */
    grid-row: span 1;

    /* Shorthand */
    grid-area: 1 / 1 / 2 / 3; /* row-start / col-start / row-end / col-end */

    /* Self alignment */
    justify-self: start;
    align-self: end;
}
```

### Grid Areas

```css
.grid-layout {
    display: grid;
    grid-template-areas:
        "header header header"
        "sidebar main main"
        "footer footer footer";
    grid-template-columns: 200px 1fr 1fr;
    grid-template-rows: 80px 1fr 60px;
}

.header { grid-area: header; }
.sidebar { grid-area: sidebar; }
.main { grid-area: main; }
.footer { grid-area: footer; }
```

### Grid Functions

```css
.grid-functions {
    /* Repeat function */
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    grid-template-columns: repeat(auto-fill, 200px);

    /* Minmax function */
    grid-template-columns: minmax(200px, 1fr) 200px;
    grid-template-rows: minmax(100px, auto);

    /* Fit-content function */
    grid-template-columns: fit-content(200px) 1fr;

    /* Auto sizing */
    grid-template-columns: auto 1fr auto;
}
```

---

## Responsive Design

### Media Queries

```css
/* Basic media query */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
}

/* Multiple conditions */
@media (min-width: 768px) and (max-width: 1200px) {
    .grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

/* Device orientation */
@media (orientation: landscape) {
    .header {
        height: 60px;
    }
}

/* Device type */
@media screen and (max-width: 768px) {
    .mobile-only {
        display: block;
    }
}

@media print {
    .no-print {
        display: none;
    }
}

/* High DPI displays */
@media (min-resolution: 2dppx) {
    .logo {
        background-image: url('logo@2x.png');
    }
}
```

### Responsive Units

```css
.responsive-units {
    /* Viewport units */
    width: 100vw;            /* 100% of viewport width */
    height: 100vh;           /* 100% of viewport height */
    font-size: 4vw;          /* 4% of viewport width */

    /* Relative units */
    font-size: 1em;          /* Relative to parent font size */
    font-size: 1rem;         /* Relative to root font size */
    margin: 2ch;             /* Width of "0" character */

    /* Percentage */
    width: 50%;              /* 50% of parent width */

    /* Flexible measurements */
    width: clamp(200px, 50%, 600px); /* Min, preferred, max */
    font-size: min(4vw, 24px);       /* Smaller value */
    width: max(200px, 50%);          /* Larger value */
}
```

### Viewport Meta Tag

```html
<!-- Essential for responsive design -->
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<!-- Additional options -->
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
```

### Mobile First Design

```css
/* Mobile first approach */
.container {
    padding: 10px;
    font-size: 14px;
}

/* Tablet */
@media (min-width: 768px) {
    .container {
        padding: 20px;
        font-size: 16px;
    }
}

/* Desktop */
@media (min-width: 1200px) {
    .container {
        padding: 30px;
        font-size: 18px;
        max-width: 1200px;
        margin: 0 auto;
    }
}
```

---

## Transformations and Animations

### 2D Transforms

```css
.transforms-2d {
    /* Translate */
    transform: translate(50px, 100px);
    transform: translateX(50px);
    transform: translateY(100px);

    /* Scale */
    transform: scale(1.5);
    transform: scale(2, 0.5);    /* x, y */
    transform: scaleX(2);
    transform: scaleY(0.5);

    /* Rotate */
    transform: rotate(45deg);
    transform: rotate(-90deg);

    /* Skew */
    transform: skew(20deg, 10deg);
    transform: skewX(20deg);
    transform: skewY(10deg);

    /* Multiple transforms */
    transform: translate(50px, 100px) rotate(45deg) scale(1.2);

    /* Transform origin */
    transform-origin: center;     /* center, top left, 50% 50%, etc */
    transform-origin: top left;
    transform-origin: 25% 75%;
}
```

### 3D Transforms

```css
.transforms-3d {
    /* 3D Translation */
    transform: translate3d(50px, 100px, 25px);
    transform: translateZ(25px);

    /* 3D Rotation */
    transform: rotateX(45deg);
    transform: rotateY(45deg);
    transform: rotateZ(45deg);
    transform: rotate3d(1, 1, 0, 45deg);

    /* 3D Scale */
    transform: scale3d(2, 1.5, 1);
    transform: scaleZ(2);

    /* Perspective */
    perspective: 1000px;
    transform-style: preserve-3d;
    backface-visibility: hidden;
}

.parent-3d {
    perspective: 1000px;
}

.child-3d {
    transform: rotateY(45deg);
}
```

### Transitions

```css
.transitions {
    /* Basic transition */
    transition: all 0.3s ease;

    /* Specific properties */
    transition: background-color 0.3s ease;
    transition: transform 0.5s ease-in-out;

    /* Multiple properties */
    transition:
        background-color 0.3s ease,
        transform 0.5s ease-in-out,
        opacity 0.2s linear;

    /* Transition timing */
    transition-duration: 0.3s;
    transition-delay: 0.1s;
    transition-timing-function: ease;     /* ease, linear, ease-in, ease-out, ease-in-out */
    transition-timing-function: cubic-bezier(0.25, 0.1, 0.25, 1);
}

.button {
    background: blue;
    transform: scale(1);
    transition: all 0.3s ease;
}

.button:hover {
    background: red;
    transform: scale(1.1);
}
```

### Animations

```css
/* Keyframes */
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

@keyframes slide {
    0% { transform: translateX(-100%); }
    50% { transform: translateX(0); }
    100% { transform: translateX(100%); }
}

@keyframes bounce {
    0%, 20%, 50%, 80%, 100% {
        transform: translateY(0);
    }
    40% {
        transform: translateY(-30px);
    }
    60% {
        transform: translateY(-15px);
    }
}

/* Animation properties */
.animated {
    animation-name: fadeIn;
    animation-duration: 2s;
    animation-timing-function: ease-in-out;
    animation-delay: 1s;
    animation-iteration-count: infinite;  /* number or infinite */
    animation-direction: alternate;       /* normal, reverse, alternate, alternate-reverse */
    animation-fill-mode: forwards;        /* none, forwards, backwards, both */
    animation-play-state: running;        /* running, paused */

    /* Shorthand */
    animation: fadeIn 2s ease-in-out 1s infinite alternate forwards;
}

/* Multiple animations */
.multi-animation {
    animation:
        fadeIn 1s ease-in,
        slide 2s ease-out 1s,
        bounce 0.5s ease infinite;
}
```

---

## Advanced Selectors

### Pseudo Classes

```css
/* Link states */
a:link { color: blue; }
a:visited { color: purple; }
a:hover { color: red; }
a:active { color: orange; }

/* Form states */
input:focus { border-color: blue; }
input:valid { border-color: green; }
input:invalid { border-color: red; }
input:required { background: #f0f0f0; }
input:disabled { opacity: 0.5; }
input:checked { background: blue; }

/* Structural pseudo-classes */
li:first-child { font-weight: bold; }
li:last-child { margin-bottom: 0; }
li:nth-child(odd) { background: #f0f0f0; }
li:nth-child(even) { background: white; }
li:nth-child(3n) { color: red; }
li:nth-child(3n+1) { color: blue; }

/* Targeting specific elements */
p:first-of-type { margin-top: 0; }
p:last-of-type { margin-bottom: 0; }
p:nth-of-type(2) { font-style: italic; }

/* Content-based */
div:empty { display: none; }
p:not(.special) { color: gray; }
```

### Pseudo Elements

```css
/* Content pseudo-elements */
.quote::before {
    content: """;
    font-size: 2em;
    color: gray;
}

.quote::after {
    content: """;
    font-size: 2em;
    color: gray;
}

/* First line and letter */
p::first-line {
    font-weight: bold;
    font-size: 1.2em;
}

p::first-letter {
    float: left;
    font-size: 3em;
    line-height: 1;
}

/* Selection styling */
::selection {
    background: yellow;
    color: black;
}

/* Placeholder styling */
input::placeholder {
    color: #999;
    font-style: italic;
}

/* File input button */
input[type="file"]::file-selector-button {
    background: blue;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 4px;
}
```

### Attribute Selectors

```css
/* Has attribute */
[href] { color: blue; }
[target] { font-weight: bold; }

/* Exact value */
[type="text"] { border: 1px solid gray; }
[class="highlight"] { background: yellow; }

/* Contains value */
[class~="button"] { padding: 10px; }  /* Class contains "button" */
[lang|="en"] { direction: ltr; }      /* Language is "en" or starts with "en-" */

/* Starts with */
[href^="https"] { color: green; }     /* Starts with "https" */
[href^="mailto"] { color: orange; }   /* Starts with "mailto" */

/* Ends with */
[href$=".pdf"] { background: url(pdf-icon.png); }
[src$=".jpg"] { border: 2px solid gray; }

/* Contains substring */
[href*="example"] { text-decoration: underline; }
[title*="important"] { font-weight: bold; }

/* Case insensitive */
[href*="EXAMPLE" i] { color: red; }
```

### Combinators

```css
/* Descendant selector (space) */
article p { color: gray; }

/* Child selector (>) */
nav > ul { list-style: none; }

/* Adjacent sibling (+) */
h1 + p { margin-top: 0; }

/* General sibling (~) */
h1 ~ p { margin-left: 20px; }

/* Complex selectors */
.sidebar nav > ul li:hover a { color: red; }
.container .content p:not(.special) { line-height: 1.6; }
form input[type="text"]:focus + label { color: blue; }
```

---

## Modern CSS

### CSS Variables

```css
/* Define variables */
:root {
    --primary-color: #007bff;
    --secondary-color: #6c757d;
    --font-size-base: 16px;
    --spacing: 20px;
    --border-radius: 8px;
    --shadow: 0 2px 4px rgba(0,0,0,0.1);
}

/* Use variables */
.button {
    background: var(--primary-color);
    color: white;
    font-size: var(--font-size-base);
    padding: var(--spacing);
    border-radius: var(--border-radius);
    box-shadow: var(--shadow);
}

/* Fallback values */
.button {
    background: var(--primary-color, blue);
}

/* Local variables */
.dark-theme {
    --primary-color: #0056b3;
    --background: #333;
    --text-color: white;
}

/* Dynamic variables */
.slider {
    --progress: 50%;
    background: linear-gradient(to right,
        var(--primary-color) var(--progress),
        #ddd var(--progress)
    );
}
```

### CSS Functions

```css
.functions {
    /* Calc function */
    width: calc(100% - 20px);
    height: calc(100vh - 80px);
    margin: calc(1rem + 10px);

    /* Min/Max functions */
    width: min(100%, 600px);
    height: max(200px, 50vh);
    font-size: clamp(1rem, 4vw, 2rem);

    /* Color functions */
    background: hsl(200, 50%, 50%);
    background: hwb(200 20% 30%);
    color: rgb(255 0 0 / 0.5);

    /* URL function */
    background-image: url('image.jpg');

    /* Counter functions */
    content: counter(section-counter);
    counter-increment: section-counter;

    /* Attribute function */
    content: attr(data-label);
}

/* Custom properties with functions */
:root {
    --size: clamp(1rem, 5vw, 3rem);
    --color: hsl(var(--hue, 200), 50%, 50%);
    --spacing: max(1rem, 3vw);
}
```

### CSS Grid Advanced

```css
.advanced-grid {
    display: grid;

    /* Subgrid */
    grid-template-columns: subgrid;
    grid-template-rows: subgrid;

    /* Named lines */
    grid-template-columns:
        [sidebar-start] 250px
        [sidebar-end main-start] 1fr
        [main-end];

    /* Dense packing */
    grid-auto-flow: row dense;

    /* Implicit grid */
    grid-auto-columns: minmax(100px, auto);
    grid-auto-rows: 100px;

    /* Complex areas */
    grid-template:
        "header header header" 100px
        "sidebar main main" 1fr
        "footer footer footer" 60px
        / 200px 1fr 1fr;
}

.grid-item {
    /* Named line positioning */
    grid-column: sidebar-start / main-end;

    /* Complex spanning */
    grid-area: header / sidebar-start / footer / main-end;
}
```

### Container Queries

```css
/* Container query */
.card-container {
    container-type: inline-size;
    container-name: card;
}

@container card (min-width: 300px) {
    .card {
        display: flex;
        flex-direction: row;
    }

    .card-image {
        width: 40%;
    }

    .card-content {
        width: 60%;
    }
}

@container (max-width: 299px) {
    .card {
        display: block;
    }

    .card-image {
        width: 100%;
    }
}

/* Container query units */
.responsive-text {
    font-size: 5cqw;    /* 5% of container width */
    padding: 2cqh;      /* 2% of container height */
    margin: 1cqi;       /* 1% of container inline size */
    border-width: 0.5cqb; /* 0.5% of container block size */
}
```

---

**CSS Resources:**
- **MDN CSS Reference**: Complete documentation
- **CSS-Tricks**: Tutorials and guides
- **Can I Use**: Browser compatibility
- **CodePen**: Examples and experimentation
- **CSS Grid Garden**: Interactive grid learning
- **Flexbox Froggy**: Interactive flexbox learning