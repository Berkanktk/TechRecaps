# HTML Learning Guide

## Table of Contents

1. [HTML Basics](#html-basics)
   1. [What is HTML](#what-is-html)
   2. [Document Structure](#document-structure)
   3. [Tags and Elements](#tags-and-elements)
   4. [Attributes](#attributes)
2. [Text Content](#text-content)
   1. [Headings](#headings)
   2. [Paragraphs](#paragraphs)
   3. [Text Formatting](#text-formatting)
   4. [Line Breaks and Spacing](#line-breaks-and-spacing)
3. [Links and Navigation](#links-and-navigation)
   1. [Basic Links](#basic-links)
   2. [Link Types](#link-types)
   3. [Anchors](#anchors)
   4. [Navigation Elements](#navigation-elements)
4. [Images and Media](#images-and-media)
   1. [Images](#images)
   2. [Audio](#audio)
   3. [Video](#video)
   4. [Responsive Images](#responsive-images)
5. [Lists](#lists)
   1. [Unordered Lists](#unordered-lists)
   2. [Ordered Lists](#ordered-lists)
   3. [Description Lists](#description-lists)
   4. [Nested Lists](#nested-lists)
6. [Tables](#tables)
   1. [Basic Tables](#basic-tables)
   2. [Table Headers](#table-headers)
   3. [Table Structure](#table-structure)
   4. [Table Styling](#table-styling)
7. [Forms](#forms)
   1. [Form Basics](#form-basics)
   2. [Input Types](#input-types)
   3. [Form Controls](#form-controls)
   4. [Validation](#validation)
8. [Semantic HTML](#semantic-html)
   1. [Structural Elements](#structural-elements)
   2. [Content Sectioning](#content-sectioning)
   3. [Text Semantics](#text-semantics)
   4. [ARIA Labels](#aria-labels)
9. [Advanced Elements](#advanced-elements)
   1. [Iframe](#iframe)
   2. [Canvas](#canvas)
   3. [SVG](#svg)
   4. [Web Components](#web-components)
10. [HTML5 Features](#html5-features)
    1. [New Input Types](#new-input-types)
    2. [Local Storage](#local-storage)
    3. [Geolocation](#geolocation)
    4. [Web Workers](#web-workers)
11. [Best Practices](#best-practices)
    1. [Accessibility](#accessibility)
    2. [SEO](#seo)
    3. [Performance](#performance)
    4. [Validation](#validation-1)
12. [Tools and Resources](#tools-and-resources)
    1. [Development Tools](#development-tools)
    2. [Validation Tools](#validation-tools)
    3. [Reference Resources](#reference-resources)

---

## HTML Basics

### What is HTML

**HTML (HyperText Markup Language)** is the standard markup language for creating web pages.

**Key Features:**
- Structure and content of web pages
- Uses tags to define elements
- Interpreted by web browsers
- Works with CSS and JavaScript

**Common Uses:**
- Websites and web applications
- Email templates
- Documentation
- Mobile app interfaces

### Document Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Title</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a paragraph.</p>
</body>
</html>
```

**Essential Elements:**
- `<!DOCTYPE html>` - HTML5 declaration
- `<html>` - Root element
- `<head>` - Metadata container
- `<body>` - Visible content

### Tags and Elements

```html
<!-- Opening and closing tags -->
<p>This is a paragraph</p>
<h1>This is a heading</h1>

<!-- Self-closing tags -->
<br>
<img src="image.jpg" alt="Description">
<input type="text">

<!-- Nested elements -->
<div>
    <p>Paragraph inside a div</p>
    <span>Span inside the div</span>
</div>

<!-- Comments -->
<!-- This is a comment -->
```

**Tag Rules:**
- Most tags come in pairs: `<tag>content</tag>`
- Some tags are self-closing: `<br>`, `<img>`, `<input>`
- Tags can be nested but must be properly closed
- Tag names are case-insensitive (lowercase preferred)

### Attributes

```html
<!-- Common attributes -->
<div id="main-content" class="container">
    <p class="highlight">Styled paragraph</p>
</div>

<img src="photo.jpg" alt="A beautiful sunset" width="300" height="200">

<a href="https://example.com" target="_blank" title="Visit Example">Link</a>

<!-- Data attributes -->
<div data-user-id="123" data-role="admin">User info</div>

<!-- Boolean attributes -->
<input type="checkbox" checked>
<input type="text" disabled>
<video controls autoplay muted>
```

**Global Attributes:**
- `id` - Unique identifier
- `class` - CSS class names
- `style` - Inline CSS
- `title` - Tooltip text
- `data-*` - Custom data attributes

---

## Text Content

### Headings

```html
<h1>Main Heading (Largest)</h1>
<h2>Section Heading</h2>
<h3>Subsection Heading</h3>
<h4>Sub-subsection Heading</h4>
<h5>Minor Heading</h5>
<h6>Smallest Heading</h6>

<!-- Proper heading hierarchy -->
<h1>Article Title</h1>
    <h2>Chapter 1</h2>
        <h3>Section 1.1</h3>
        <h3>Section 1.2</h3>
    <h2>Chapter 2</h2>
        <h3>Section 2.1</h3>
```

**Best Practices:**
- Use only one `<h1>` per page
- Don't skip heading levels
- Use headings for structure, not styling

### Paragraphs

```html
<p>This is a regular paragraph with some text content.</p>

<p>This is another paragraph. It can contain
multiple lines of text that will flow together.</p>

<!-- Paragraph with inline elements -->
<p>This paragraph contains <strong>bold text</strong> and <em>italic text</em>.</p>

<!-- Long paragraph -->
<p>
    Lorem ipsum dolor sit amet, consectetur adipiscing elit.
    Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
    Ut enim ad minim veniam, quis nostrud exercitation.
</p>
```

### Text Formatting

```html
<!-- Bold and italic -->
<strong>Important text (semantic bold)</strong>
<b>Bold text (visual only)</b>
<em>Emphasized text (semantic italic)</em>
<i>Italic text (visual only)</i>

<!-- Other formatting -->
<mark>Highlighted text</mark>
<small>Small print text</small>
<del>Deleted text</del>
<ins>Inserted text</ins>
<sub>Subscript</sub>
<sup>Superscript</sup>

<!-- Code formatting -->
<code>console.log('Hello');</code>
<kbd>Ctrl + C</kbd>
<samp>Output text</samp>
<var>variable_name</var>

<!-- Quotations -->
<q>Short inline quote</q>
<blockquote cite="source-url">
    <p>Long block quote that stands alone.</p>
</blockquote>

<!-- Abbreviations -->
<abbr title="HyperText Markup Language">HTML</abbr>
```

### Line Breaks and Spacing

```html
<!-- Line breaks -->
<p>First line<br>Second line<br>Third line</p>

<!-- Horizontal rule -->
<hr>

<!-- Preformatted text -->
<pre>
    This text preserves
        spaces and line breaks
            exactly as written.
</pre>

<!-- Address -->
<address>
    John Doe<br>
    123 Main Street<br>
    City, State 12345
</address>
```

---

## Links and Navigation

### Basic Links

```html
<!-- External link -->
<a href="https://example.com">Visit Example</a>

<!-- Internal link -->
<a href="about.html">About Page</a>

<!-- Link with title -->
<a href="contact.html" title="Get in touch">Contact Us</a>

<!-- Email link -->
<a href="mailto:user@example.com">Send Email</a>

<!-- Phone link -->
<a href="tel:+1234567890">Call Us</a>

<!-- Download link -->
<a href="document.pdf" download>Download PDF</a>
```

### Link Types

```html
<!-- Target attributes -->
<a href="page.html" target="_blank">Open in new tab</a>
<a href="page.html" target="_self">Open in same window</a>
<a href="page.html" target="_parent">Open in parent frame</a>

<!-- Relationship attributes -->
<a href="next.html" rel="next">Next Page</a>
<a href="prev.html" rel="prev">Previous Page</a>
<a href="external.com" rel="nofollow">External Link</a>

<!-- Button-style links -->
<a href="action.html" role="button">Action Button</a>
```

### Anchors

```html
<!-- Create anchor -->
<h2 id="section1">Section 1</h2>
<p>Content for section 1...</p>

<h2 id="section2">Section 2</h2>
<p>Content for section 2...</p>

<!-- Link to anchors -->
<a href="#section1">Go to Section 1</a>
<a href="#section2">Go to Section 2</a>
<a href="#top">Back to Top</a>

<!-- External page anchor -->
<a href="other-page.html#specific-section">Other Page Section</a>
```

### Navigation Elements

```html
<!-- Navigation menu -->
<nav>
    <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/about">About</a></li>
        <li><a href="/services">Services</a></li>
        <li><a href="/contact">Contact</a></li>
    </ul>
</nav>

<!-- Breadcrumb navigation -->
<nav aria-label="Breadcrumb">
    <ol>
        <li><a href="/">Home</a></li>
        <li><a href="/category">Category</a></li>
        <li aria-current="page">Current Page</li>
    </ol>
</nav>

<!-- Skip link for accessibility -->
<a href="#main-content" class="skip-link">Skip to main content</a>
```

---

## Images and Media

### Images

```html
<!-- Basic image -->
<img src="photo.jpg" alt="Description of the image">

<!-- Image with dimensions -->
<img src="photo.jpg" alt="Photo" width="300" height="200">

<!-- Figure with caption -->
<figure>
    <img src="chart.png" alt="Sales data chart">
    <figcaption>Sales increased by 25% this quarter</figcaption>
</figure>

<!-- Image map -->
<img src="map.jpg" alt="World map" usemap="#worldmap">
<map name="worldmap">
    <area shape="rect" coords="0,0,100,100" href="usa.html" alt="USA">
    <area shape="circle" coords="200,200,50" href="europe.html" alt="Europe">
</map>

<!-- Lazy loading -->
<img src="image.jpg" alt="Description" loading="lazy">
```

### Audio

```html
<!-- Basic audio -->
<audio controls>
    <source src="audio.mp3" type="audio/mpeg">
    <source src="audio.ogg" type="audio/ogg">
    Your browser does not support audio.
</audio>

<!-- Audio with attributes -->
<audio controls autoplay muted loop>
    <source src="music.mp3" type="audio/mpeg">
</audio>

<!-- Audio with download fallback -->
<audio controls>
    <source src="podcast.mp3" type="audio/mpeg">
    <p>Your browser doesn't support audio.
    <a href="podcast.mp3">Download the file</a> instead.</p>
</audio>
```

### Video

```html
<!-- Basic video -->
<video controls width="600" height="400">
    <source src="video.mp4" type="video/mp4">
    <source src="video.webm" type="video/webm">
    Your browser does not support video.
</video>

<!-- Video with poster -->
<video controls poster="thumbnail.jpg">
    <source src="movie.mp4" type="video/mp4">
</video>

<!-- Video with attributes -->
<video controls autoplay muted loop width="100%">
    <source src="background.mp4" type="video/mp4">
</video>

<!-- Video with subtitles -->
<video controls>
    <source src="movie.mp4" type="video/mp4">
    <track kind="subtitles" src="subtitles-en.vtt" srclang="en" label="English">
    <track kind="subtitles" src="subtitles-es.vtt" srclang="es" label="Spanish">
</video>
```

### Responsive Images

```html
<!-- Responsive image with srcset -->
<img src="small.jpg"
     srcset="small.jpg 400w, medium.jpg 800w, large.jpg 1200w"
     sizes="(max-width: 400px) 100vw, (max-width: 800px) 50vw, 25vw"
     alt="Responsive image">

<!-- Picture element for art direction -->
<picture>
    <source media="(max-width: 600px)" srcset="mobile.jpg">
    <source media="(max-width: 1024px)" srcset="tablet.jpg">
    <img src="desktop.jpg" alt="Adaptive image">
</picture>

<!-- WebP with fallback -->
<picture>
    <source srcset="image.webp" type="image/webp">
    <source srcset="image.jpg" type="image/jpeg">
    <img src="image.jpg" alt="Image with format fallback">
</picture>
```

---

## Lists

### Unordered Lists

```html
<!-- Basic unordered list -->
<ul>
    <li>First item</li>
    <li>Second item</li>
    <li>Third item</li>
</ul>

<!-- List with links -->
<ul>
    <li><a href="page1.html">Page 1</a></li>
    <li><a href="page2.html">Page 2</a></li>
    <li><a href="page3.html">Page 3</a></li>
</ul>

<!-- List with formatting -->
<ul>
    <li><strong>Important item</strong></li>
    <li><em>Emphasized item</em></li>
    <li>Regular item</li>
</ul>
```

### Ordered Lists

```html
<!-- Basic ordered list -->
<ol>
    <li>First step</li>
    <li>Second step</li>
    <li>Third step</li>
</ol>

<!-- Ordered list with custom start -->
<ol start="5">
    <li>Fifth item</li>
    <li>Sixth item</li>
    <li>Seventh item</li>
</ol>

<!-- Reversed ordered list -->
<ol reversed>
    <li>Last item</li>
    <li>Second to last</li>
    <li>First item</li>
</ol>

<!-- Different numbering types -->
<ol type="A">
    <li>Item A</li>
    <li>Item B</li>
    <li>Item C</li>
</ol>

<ol type="i">
    <li>Item i</li>
    <li>Item ii</li>
    <li>Item iii</li>
</ol>
```

### Description Lists

```html
<!-- Description list -->
<dl>
    <dt>HTML</dt>
    <dd>HyperText Markup Language</dd>

    <dt>CSS</dt>
    <dd>Cascading Style Sheets</dd>

    <dt>JavaScript</dt>
    <dd>Programming language for web pages</dd>
    <dd>Also used for server-side development</dd>
</dl>

<!-- Complex description list -->
<dl>
    <dt>Name</dt>
    <dd>John Doe</dd>

    <dt>Position</dt>
    <dd>Web Developer</dd>

    <dt>Skills</dt>
    <dd>HTML, CSS, JavaScript</dd>
    <dd>React, Node.js</dd>
    <dd>Python, Django</dd>
</dl>
```

### Nested Lists

```html
<!-- Nested unordered lists -->
<ul>
    <li>Fruits
        <ul>
            <li>Apples</li>
            <li>Oranges</li>
            <li>Bananas</li>
        </ul>
    </li>
    <li>Vegetables
        <ul>
            <li>Carrots</li>
            <li>Broccoli</li>
        </ul>
    </li>
</ul>

<!-- Mixed nested lists -->
<ol>
    <li>Setup
        <ol type="a">
            <li>Install software</li>
            <li>Configure settings</li>
        </ol>
    </li>
    <li>Development
        <ul>
            <li>Write code</li>
            <li>Test functionality</li>
        </ul>
    </li>
</ol>
```

---

## Tables

### Basic Tables

```html
<!-- Simple table -->
<table>
    <tr>
        <td>Cell 1</td>
        <td>Cell 2</td>
        <td>Cell 3</td>
    </tr>
    <tr>
        <td>Cell 4</td>
        <td>Cell 5</td>
        <td>Cell 6</td>
    </tr>
</table>

<!-- Table with border -->
<table border="1">
    <tr>
        <td>Data 1</td>
        <td>Data 2</td>
    </tr>
    <tr>
        <td>Data 3</td>
        <td>Data 4</td>
    </tr>
</table>
```

### Table Headers

```html
<!-- Table with headers -->
<table>
    <tr>
        <th>Name</th>
        <th>Age</th>
        <th>City</th>
    </tr>
    <tr>
        <td>Alice</td>
        <td>30</td>
        <td>New York</td>
    </tr>
    <tr>
        <td>Bob</td>
        <td>25</td>
        <td>London</td>
    </tr>
</table>

<!-- Table with row headers -->
<table>
    <tr>
        <th>Product</th>
        <td>Laptop</td>
        <td>Phone</td>
        <td>Tablet</td>
    </tr>
    <tr>
        <th>Price</th>
        <td>$999</td>
        <td>$699</td>
        <td>$399</td>
    </tr>
</table>
```

### Table Structure

```html
<!-- Structured table -->
<table>
    <caption>Employee Information</caption>
    <thead>
        <tr>
            <th>Name</th>
            <th>Department</th>
            <th>Salary</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Alice Johnson</td>
            <td>Engineering</td>
            <td>$85,000</td>
        </tr>
        <tr>
            <td>Bob Smith</td>
            <td>Marketing</td>
            <td>$65,000</td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <th>Total</th>
            <th>2 Employees</th>
            <th>$150,000</th>
        </tr>
    </tfoot>
</table>

<!-- Table with column groups -->
<table>
    <colgroup>
        <col style="background-color: #f0f0f0;">
        <col span="2" style="background-color: #e0e0e0;">
    </colgroup>
    <tr>
        <th>Name</th>
        <th>Q1</th>
        <th>Q2</th>
    </tr>
    <tr>
        <td>Sales</td>
        <td>$100k</td>
        <td>$120k</td>
    </tr>
</table>
```

### Table Styling

```html
<!-- Table with spanning cells -->
<table>
    <tr>
        <th colspan="3">Sales Report</th>
    </tr>
    <tr>
        <th>Product</th>
        <th>Q1</th>
        <th>Q2</th>
    </tr>
    <tr>
        <td>Laptops</td>
        <td>100</td>
        <td>120</td>
    </tr>
    <tr>
        <td rowspan="2">Phones</td>
        <td>80</td>
        <td>90</td>
    </tr>
    <tr>
        <td>75</td>
        <td>85</td>
    </tr>
</table>

<!-- Accessible table -->
<table>
    <caption>Monthly Sales Data</caption>
    <thead>
        <tr>
            <th scope="col">Month</th>
            <th scope="col">Sales</th>
            <th scope="col">Growth</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th scope="row">January</th>
            <td>$50,000</td>
            <td>5%</td>
        </tr>
        <tr>
            <th scope="row">February</th>
            <td>$55,000</td>
            <td>10%</td>
        </tr>
    </tbody>
</table>
```

---

## Forms

### Form Basics

```html
<!-- Basic form -->
<form action="/submit" method="post">
    <label for="name">Name:</label>
    <input type="text" id="name" name="name" required>

    <label for="email">Email:</label>
    <input type="email" id="email" name="email" required>

    <button type="submit">Submit</button>
</form>

<!-- Form with fieldset -->
<form>
    <fieldset>
        <legend>Personal Information</legend>
        <label for="fname">First Name:</label>
        <input type="text" id="fname" name="fname">

        <label for="lname">Last Name:</label>
        <input type="text" id="lname" name="lname">
    </fieldset>

    <fieldset>
        <legend>Contact Information</legend>
        <label for="phone">Phone:</label>
        <input type="tel" id="phone" name="phone">
    </fieldset>
</form>
```

### Input Types

```html
<!-- Text inputs -->
<input type="text" placeholder="Enter text">
<input type="password" placeholder="Enter password">
<input type="email" placeholder="Enter email">
<input type="url" placeholder="Enter URL">
<input type="tel" placeholder="Enter phone">
<input type="search" placeholder="Search...">

<!-- Number inputs -->
<input type="number" min="0" max="100" step="1">
<input type="range" min="0" max="100" value="50">

<!-- Date and time inputs -->
<input type="date">
<input type="time">
<input type="datetime-local">
<input type="month">
<input type="week">

<!-- Other inputs -->
<input type="color" value="#ff0000">
<input type="file" accept=".jpg,.png,.pdf">
<input type="hidden" name="token" value="abc123">

<!-- Checkboxes and radio buttons -->
<input type="checkbox" id="agree" name="agree">
<label for="agree">I agree to terms</label>

<input type="radio" id="male" name="gender" value="male">
<label for="male">Male</label>
<input type="radio" id="female" name="gender" value="female">
<label for="female">Female</label>
```

### Form Controls

```html
<!-- Textarea -->
<label for="message">Message:</label>
<textarea id="message" name="message" rows="4" cols="50" placeholder="Enter your message"></textarea>

<!-- Select dropdown -->
<label for="country">Country:</label>
<select id="country" name="country">
    <option value="">Select a country</option>
    <option value="us">United States</option>
    <option value="uk">United Kingdom</option>
    <option value="ca">Canada</option>
</select>

<!-- Multiple select -->
<label for="skills">Skills:</label>
<select id="skills" name="skills" multiple>
    <option value="html">HTML</option>
    <option value="css">CSS</option>
    <option value="js">JavaScript</option>
    <option value="python">Python</option>
</select>

<!-- Datalist (autocomplete) -->
<label for="browser">Choose a browser:</label>
<input list="browsers" id="browser" name="browser">
<datalist id="browsers">
    <option value="Chrome">
    <option value="Firefox">
    <option value="Safari">
    <option value="Edge">
</datalist>

<!-- Buttons -->
<button type="submit">Submit Form</button>
<button type="reset">Reset Form</button>
<button type="button" onclick="doSomething()">Custom Action</button>
<input type="submit" value="Submit">
<input type="reset" value="Reset">
```

### Validation

```html
<!-- Required fields -->
<input type="text" name="name" required>
<input type="email" name="email" required>

<!-- Pattern validation -->
<input type="text" name="phone" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}"
       title="Format: 123-456-7890">

<!-- Length validation -->
<input type="text" name="username" minlength="3" maxlength="20">
<textarea name="bio" maxlength="500"></textarea>

<!-- Number validation -->
<input type="number" name="age" min="18" max="120">
<input type="range" name="rating" min="1" max="5" step="0.5">

<!-- Custom validation messages -->
<input type="email" name="email" required
       oninvalid="this.setCustomValidity('Please enter a valid email address')"
       oninput="this.setCustomValidity('')">

<!-- Form validation example -->
<form novalidate>
    <label for="username">Username (3-20 characters):</label>
    <input type="text" id="username" name="username"
           minlength="3" maxlength="20" required>

    <label for="password">Password (min 8 characters):</label>
    <input type="password" id="password" name="password"
           minlength="8" required>

    <label for="confirm">Confirm Password:</label>
    <input type="password" id="confirm" name="confirm"
           required oninput="checkPasswordMatch()">

    <button type="submit">Create Account</button>
</form>

<script>
function checkPasswordMatch() {
    const password = document.getElementById('password');
    const confirm = document.getElementById('confirm');

    if (password.value !== confirm.value) {
        confirm.setCustomValidity('Passwords do not match');
    } else {
        confirm.setCustomValidity('');
    }
}
</script>
```

---

## Semantic HTML

### Structural Elements

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Semantic HTML Example</title>
</head>
<body>
    <!-- Page header -->
    <header>
        <h1>Website Name</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/about">About</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </nav>
    </header>

    <!-- Main content -->
    <main>
        <article>
            <header>
                <h2>Article Title</h2>
                <p>Published on <time datetime="2024-03-15">March 15, 2024</time></p>
            </header>

            <section>
                <h3>Introduction</h3>
                <p>Article introduction...</p>
            </section>

            <section>
                <h3>Main Content</h3>
                <p>Main article content...</p>
            </section>

            <footer>
                <p>Author: John Doe</p>
            </footer>
        </article>

        <aside>
            <h3>Related Articles</h3>
            <ul>
                <li><a href="/article1">Article 1</a></li>
                <li><a href="/article2">Article 2</a></li>
            </ul>
        </aside>
    </main>

    <!-- Page footer -->
    <footer>
        <p>&copy; 2024 Website Name. All rights reserved.</p>
    </footer>
</body>
</html>
```

### Content Sectioning

```html
<!-- Article -->
<article>
    <h2>Blog Post Title</h2>
    <p>This is a standalone piece of content...</p>
</article>

<!-- Section -->
<section>
    <h2>Products</h2>
    <div class="product">Product 1</div>
    <div class="product">Product 2</div>
</section>

<!-- Aside -->
<aside>
    <h3>Advertisement</h3>
    <p>Related content or sidebar information</p>
</aside>

<!-- Navigation -->
<nav aria-label="Main navigation">
    <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/products">Products</a></li>
        <li><a href="/services">Services</a></li>
    </ul>
</nav>

<!-- Details and summary -->
<details>
    <summary>Click to expand</summary>
    <p>Hidden content that can be revealed</p>
    <ul>
        <li>Item 1</li>
        <li>Item 2</li>
    </ul>
</details>
```

### Text Semantics

```html
<!-- Time element -->
<p>Published on <time datetime="2024-03-15T10:30:00">March 15, 2024 at 10:30 AM</time></p>

<!-- Progress and meter -->
<label for="progress">Loading:</label>
<progress id="progress" value="75" max="100">75%</progress>

<label for="score">Score:</label>
<meter id="score" value="8" min="0" max="10">8 out of 10</meter>

<!-- Definition -->
<p>The <dfn>DOM</dfn> is the Document Object Model.</p>

<!-- Ruby annotations (for East Asian typography) -->
<ruby>
    漢字 <rt>かんじ</rt>
</ruby>

<!-- Data element -->
<data value="2024-03-15">March 15, 2024</data>

<!-- Output element -->
<form oninput="result.value=parseInt(a.value)+parseInt(b.value)">
    <input type="range" id="a" value="50">
    +<input type="number" id="b" value="50">
    =<output name="result" for="a b">100</output>
</form>
```

### ARIA Labels

```html
<!-- ARIA landmarks -->
<header role="banner">
    <h1>Site Title</h1>
</header>

<nav role="navigation" aria-label="Main menu">
    <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/about">About</a></li>
    </ul>
</nav>

<main role="main">
    <h2>Main Content</h2>
</main>

<!-- ARIA labels and descriptions -->
<button aria-label="Close dialog">×</button>

<input type="password" aria-describedby="pwd-help">
<div id="pwd-help">Password must be at least 8 characters</div>

<!-- ARIA states -->
<button aria-expanded="false" aria-controls="menu">Menu</button>
<ul id="menu" aria-hidden="true">
    <li>Item 1</li>
    <li>Item 2</li>
</ul>

<!-- ARIA live regions -->
<div aria-live="polite" id="status"></div>
<div aria-live="assertive" id="alerts"></div>

<!-- ARIA roles -->
<div role="button" tabindex="0">Custom Button</div>
<div role="alert">Error message</div>
<div role="tab" aria-selected="true">Tab 1</div>
```

---

## Advanced Elements

### Iframe

```html
<!-- Basic iframe -->
<iframe src="https://example.com" width="600" height="400"></iframe>

<!-- Iframe with title -->
<iframe src="map.html" title="Interactive map" width="100%" height="300"></iframe>

<!-- Sandbox iframe -->
<iframe src="untrusted.html" sandbox="allow-scripts allow-same-origin"></iframe>

<!-- Responsive iframe -->
<div style="position: relative; width: 100%; height: 0; padding-bottom: 56.25%;">
    <iframe src="video.html"
            style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;"
            frameborder="0"></iframe>
</div>

<!-- YouTube embed -->
<iframe width="560" height="315"
        src="https://www.youtube.com/embed/VIDEO_ID"
        title="YouTube video player"
        frameborder="0"
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
        allowfullscreen></iframe>
```

### Canvas

```html
<!-- Canvas element -->
<canvas id="myCanvas" width="400" height="300">
    Your browser does not support the canvas element.
</canvas>

<script>
const canvas = document.getElementById('myCanvas');
const ctx = canvas.getContext('2d');

// Draw rectangle
ctx.fillStyle = 'blue';
ctx.fillRect(10, 10, 100, 80);

// Draw circle
ctx.beginPath();
ctx.arc(200, 150, 50, 0, 2 * Math.PI);
ctx.fillStyle = 'red';
ctx.fill();

// Draw text
ctx.font = '20px Arial';
ctx.fillStyle = 'black';
ctx.fillText('Hello Canvas!', 50, 200);
</script>

<!-- Canvas with fallback -->
<canvas id="chart" width="500" height="300">
    <img src="chart-fallback.png" alt="Sales chart showing 25% increase">
</canvas>
```

### SVG

```html
<!-- Inline SVG -->
<svg width="200" height="200">
    <circle cx="100" cy="100" r="50" fill="blue" />
    <rect x="50" y="50" width="100" height="100" fill="red" opacity="0.5" />
    <text x="100" y="180" text-anchor="middle">SVG Text</text>
</svg>

<!-- SVG with viewBox -->
<svg viewBox="0 0 100 100" width="200" height="200">
    <circle cx="50" cy="50" r="40" stroke="black" stroke-width="2" fill="yellow" />
</svg>

<!-- SVG icon -->
<svg class="icon" width="24" height="24" viewBox="0 0 24 24">
    <path d="M12 2L2 7v10c0 5.55 3.84 10 9 11 5.16-1 9-5.45 9-11V7l-10-5z" fill="currentColor"/>
</svg>

<!-- SVG with animation -->
<svg width="200" height="200">
    <circle cx="100" cy="100" r="50" fill="blue">
        <animate attributeName="r" values="50;70;50" dur="2s" repeatCount="indefinite"/>
    </circle>
</svg>
```

### Web Components

```html
<!-- Custom element -->
<script>
class UserCard extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.shadowRoot.innerHTML = `
            <style>
                .card {
                    border: 1px solid #ccc;
                    border-radius: 8px;
                    padding: 16px;
                    margin: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .name { font-weight: bold; font-size: 1.2em; }
                .email { color: #666; }
            </style>
            <div class="card">
                <div class="name">${this.getAttribute('name')}</div>
                <div class="email">${this.getAttribute('email')}</div>
            </div>
        `;
    }
}

customElements.define('user-card', UserCard);
</script>

<!-- Using the custom element -->
<user-card name="John Doe" email="john@example.com"></user-card>
<user-card name="Jane Smith" email="jane@example.com"></user-card>

<!-- Template element -->
<template id="product-template">
    <div class="product">
        <h3 class="product-name"></h3>
        <p class="product-price"></p>
        <button class="add-to-cart">Add to Cart</button>
    </div>
</template>

<script>
function createProduct(name, price) {
    const template = document.getElementById('product-template');
    const clone = template.content.cloneNode(true);

    clone.querySelector('.product-name').textContent = name;
    clone.querySelector('.product-price').textContent = price;

    return clone;
}

// Use the template
const product = createProduct('Laptop', '$999');
document.body.appendChild(product);
</script>
```

---

## HTML5 Features

### New Input Types

```html
<!-- HTML5 input types -->
<form>
    <!-- Email with validation -->
    <input type="email" placeholder="Enter email" required>

    <!-- URL with validation -->
    <input type="url" placeholder="Enter website URL">

    <!-- Number with min/max -->
    <input type="number" min="1" max="10" value="5">

    <!-- Range slider -->
    <input type="range" min="0" max="100" value="50"
           oninput="document.getElementById('rangeValue').textContent = this.value">
    <span id="rangeValue">50</span>

    <!-- Date picker -->
    <input type="date" value="2024-03-15">

    <!-- Time picker -->
    <input type="time" value="14:30">

    <!-- Color picker -->
    <input type="color" value="#ff0000">

    <!-- Search with autocomplete -->
    <input type="search" placeholder="Search..." list="suggestions">
    <datalist id="suggestions">
        <option value="HTML">
        <option value="CSS">
        <option value="JavaScript">
    </datalist>

    <!-- File upload with accept -->
    <input type="file" accept="image/*" multiple>

    <!-- Tel for phone numbers -->
    <input type="tel" placeholder="Phone number" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}">
</form>
```

### Local Storage

```html
<script>
// Check if localStorage is supported
if (typeof(Storage) !== "undefined") {
    // Store data
    localStorage.setItem("username", "john_doe");
    localStorage.setItem("preferences", JSON.stringify({
        theme: "dark",
        language: "en"
    }));

    // Retrieve data
    const username = localStorage.getItem("username");
    const preferences = JSON.parse(localStorage.getItem("preferences"));

    // Remove data
    localStorage.removeItem("username");

    // Clear all data
    localStorage.clear();

    // Session storage (cleared when tab closes)
    sessionStorage.setItem("temp_data", "temporary");

    // Storage event listener
    window.addEventListener('storage', function(e) {
        console.log('Storage changed:', e.key, e.oldValue, e.newValue);
    });
} else {
    console.log("LocalStorage not supported");
}

// IndexedDB for larger data
const request = indexedDB.open("MyDatabase", 1);

request.onsuccess = function(event) {
    const db = event.target.result;
    console.log("Database opened successfully");
};

request.onerror = function(event) {
    console.log("Database error:", event.target.error);
};
</script>
```

### Geolocation

```html
<button onclick="getLocation()">Get My Location</button>
<div id="location"></div>

<script>
function getLocation() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(showPosition, showError);
    } else {
        document.getElementById("location").innerHTML =
            "Geolocation is not supported by this browser.";
    }
}

function showPosition(position) {
    const lat = position.coords.latitude;
    const lon = position.coords.longitude;

    document.getElementById("location").innerHTML =
        `Latitude: ${lat}<br>Longitude: ${lon}`;
}

function showError(error) {
    switch(error.code) {
        case error.PERMISSION_DENIED:
            document.getElementById("location").innerHTML =
                "User denied the request for Geolocation.";
            break;
        case error.POSITION_UNAVAILABLE:
            document.getElementById("location").innerHTML =
                "Location information is unavailable.";
            break;
        case error.TIMEOUT:
            document.getElementById("location").innerHTML =
                "The request to get user location timed out.";
            break;
        default:
            document.getElementById("location").innerHTML =
                "An unknown error occurred.";
            break;
    }
}

// Watch position for continuous updates
const watchId = navigator.geolocation.watchPosition(
    showPosition,
    showError,
    {
        enableHighAccuracy: true,
        timeout: 5000,
        maximumAge: 0
    }
);

// Stop watching
// navigator.geolocation.clearWatch(watchId);
</script>
```

### Web Workers

```html
<!-- Main HTML file -->
<button onclick="startWorker()">Start Worker</button>
<button onclick="stopWorker()">Stop Worker</button>
<div id="result"></div>

<script>
let worker;

function startWorker() {
    if (typeof(Worker) !== "undefined") {
        if (typeof(worker) == "undefined") {
            worker = new Worker("worker.js");
        }

        worker.onmessage = function(event) {
            document.getElementById("result").innerHTML = event.data;
        };

        // Send data to worker
        worker.postMessage({command: 'start', data: 1000000});
    } else {
        document.getElementById("result").innerHTML =
            "Sorry, your browser does not support Web Workers...";
    }
}

function stopWorker() {
    if (worker) {
        worker.terminate();
        worker = undefined;
    }
}
</script>

<!-- worker.js file -->
<script>
// This would be in a separate worker.js file
self.onmessage = function(event) {
    const data = event.data;

    if (data.command === 'start') {
        // Perform heavy computation
        let result = 0;
        for (let i = 0; i < data.data; i++) {
            result += Math.sqrt(i);
        }

        // Send result back to main thread
        self.postMessage(`Computation complete: ${result}`);
    }
};

// Handle errors
self.onerror = function(error) {
    console.log('Worker error:', error);
};
</script>
```

---

## Best Practices

### Accessibility

```html
<!-- Semantic HTML -->
<header>
    <h1>Page Title</h1>
    <nav aria-label="Main navigation">
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/about">About</a></li>
        </ul>
    </nav>
</header>

<!-- Proper heading hierarchy -->
<h1>Main Title</h1>
    <h2>Section Title</h2>
        <h3>Subsection Title</h3>
    <h2>Another Section</h2>

<!-- Alt text for images -->
<img src="chart.png" alt="Sales increased 25% from Q1 to Q2">
<img src="logo.png" alt="Company Name" role="img">
<img src="decoration.png" alt="" role="presentation">

<!-- Form accessibility -->
<form>
    <label for="email">Email Address:</label>
    <input type="email" id="email" name="email" required
           aria-describedby="email-error">
    <div id="email-error" aria-live="polite"></div>

    <fieldset>
        <legend>Preferred Contact Method</legend>
        <input type="radio" id="phone" name="contact" value="phone">
        <label for="phone">Phone</label>
        <input type="radio" id="email-contact" name="contact" value="email">
        <label for="email-contact">Email</label>
    </fieldset>
</form>

<!-- Skip links -->
<a href="#main-content" class="skip-link">Skip to main content</a>

<!-- Focus management -->
<button onclick="openModal()" aria-haspopup="dialog">Open Modal</button>
<div id="modal" role="dialog" aria-labelledby="modal-title" aria-hidden="true">
    <h2 id="modal-title">Modal Title</h2>
    <button onclick="closeModal()">Close</button>
</div>

<!-- Table accessibility -->
<table>
    <caption>Monthly Sales Report</caption>
    <thead>
        <tr>
            <th scope="col">Month</th>
            <th scope="col">Sales</th>
            <th scope="col">Growth</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th scope="row">January</th>
            <td>$10,000</td>
            <td>5%</td>
        </tr>
    </tbody>
</table>

<!-- ARIA live regions -->
<div aria-live="polite" id="status-message"></div>
<div aria-live="assertive" id="error-message"></div>
```

### SEO

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- Title and description -->
    <title>Page Title - Site Name</title>
    <meta name="description" content="Concise description of the page content for search engines">

    <!-- Keywords (less important now) -->
    <meta name="keywords" content="html, web development, tutorial">

    <!-- Open Graph for social media -->
    <meta property="og:title" content="Page Title">
    <meta property="og:description" content="Page description for social sharing">
    <meta property="og:image" content="https://example.com/image.jpg">
    <meta property="og:url" content="https://example.com/page">
    <meta property="og:type" content="website">

    <!-- Twitter Cards -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Page Title">
    <meta name="twitter:description" content="Page description for Twitter">
    <meta name="twitter:image" content="https://example.com/image.jpg">

    <!-- Canonical URL -->
    <link rel="canonical" href="https://example.com/canonical-url">

    <!-- Structured data (JSON-LD) -->
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": "Article Title",
        "author": {
            "@type": "Person",
            "name": "Author Name"
        },
        "datePublished": "2024-03-15",
        "description": "Article description"
    }
    </script>
</head>
<body>
    <!-- Semantic structure -->
    <header>
        <h1>Main Heading (Only One Per Page)</h1>
    </header>

    <nav>
        <!-- Breadcrumb navigation -->
        <ol itemscope itemtype="https://schema.org/BreadcrumbList">
            <li itemprop="itemListElement" itemscope itemtype="https://schema.org/ListItem">
                <a itemprop="item" href="/"><span itemprop="name">Home</span></a>
                <meta itemprop="position" content="1" />
            </li>
            <li itemprop="itemListElement" itemscope itemtype="https://schema.org/ListItem">
                <a itemprop="item" href="/category"><span itemprop="name">Category</span></a>
                <meta itemprop="position" content="2" />
            </li>
        </ol>
    </nav>

    <main>
        <article>
            <h2>Article Title</h2>
            <time datetime="2024-03-15">March 15, 2024</time>
            <p>Article content with relevant keywords naturally included...</p>
        </article>
    </main>
</body>
</html>
```

### Performance

```html
<!-- Critical resource hints -->
<head>
    <!-- DNS prefetch -->
    <link rel="dns-prefetch" href="//fonts.googleapis.com">

    <!-- Preconnect -->
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

    <!-- Preload critical resources -->
    <link rel="preload" href="critical.css" as="style">
    <link rel="preload" href="hero-image.jpg" as="image">
    <link rel="preload" href="font.woff2" as="font" type="font/woff2" crossorigin>

    <!-- Prefetch future resources -->
    <link rel="prefetch" href="next-page.html">

    <!-- Critical CSS inline -->
    <style>
        /* Critical above-the-fold CSS */
        .header { /* styles */ }
    </style>

    <!-- Non-critical CSS -->
    <link rel="stylesheet" href="styles.css" media="print" onload="this.media='all'">
</head>

<body>
    <!-- Optimized images -->
    <picture>
        <source srcset="hero.webp" type="image/webp">
        <source srcset="hero.jpg" type="image/jpeg">
        <img src="hero.jpg" alt="Hero image" loading="lazy" width="800" height="400">
    </picture>

    <!-- Lazy loading -->
    <img src="placeholder.jpg" data-src="actual-image.jpg" alt="Description" loading="lazy">

    <!-- Async/defer scripts -->
    <script src="critical.js"></script>
    <script src="analytics.js" async></script>
    <script src="enhancement.js" defer></script>

    <!-- Service Worker registration -->
    <script>
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js');
    }
    </script>

    <!-- Minimize DOM depth -->
    <main>
        <section class="hero">
            <h1>Title</h1>
            <p>Description</p>
        </section>
    </main>
</body>
```

### Validation

```html
<!-- HTML5 form validation -->
<form novalidate>
    <!-- Required field -->
    <input type="text" name="name" required
           title="Please enter your full name">

    <!-- Email validation -->
    <input type="email" name="email" required
           title="Please enter a valid email address">

    <!-- Pattern validation -->
    <input type="tel" name="phone"
           pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}"
           title="Format: 123-456-7890">

    <!-- Length validation -->
    <input type="password" name="password"
           minlength="8" maxlength="50" required
           title="Password must be 8-50 characters">

    <!-- Number range -->
    <input type="number" name="age"
           min="18" max="120" required>

    <!-- Custom validation -->
    <input type="password" name="confirm-password"
           oninput="validatePasswordMatch(this)">

    <button type="submit">Submit</button>
</form>

<script>
function validatePasswordMatch(input) {
    const password = document.querySelector('input[name="password"]').value;
    const confirmPassword = input.value;

    if (password !== confirmPassword) {
        input.setCustomValidity('Passwords do not match');
    } else {
        input.setCustomValidity('');
    }
}

// Form submission handling
document.querySelector('form').addEventListener('submit', function(e) {
    e.preventDefault();

    if (this.checkValidity()) {
        // Form is valid, submit data
        console.log('Form is valid, submitting...');
    } else {
        // Show validation errors
        const firstInvalid = this.querySelector(':invalid');
        if (firstInvalid) {
            firstInvalid.focus();
        }
    }
});
</script>

<!-- W3C Markup Validation -->
<!-- Add this comment for validation: -->
<!-- HTML validated with W3C Markup Validator -->

<!-- DOCTYPE declaration -->
<!DOCTYPE html>

<!-- Language declaration -->
<html lang="en">

<!-- Character encoding -->
<meta charset="UTF-8">

<!-- Properly nested elements -->
<div>
    <p>Paragraph inside div</p>
    <span>Span inside div</span>
</div>

<!-- Quoted attributes -->
<img src="image.jpg" alt="Description" width="300" height="200">

<!-- Closed tags -->
<p>Paragraph with proper closing tag</p>
<br>
<input type="text" name="field">
```

---

## Tools and Resources

### Development Tools

```html
<!-- Browser Developer Tools -->
<!--
F12 - Open DevTools
Ctrl+Shift+I - Inspect Element
Ctrl+Shift+C - Select Element
Ctrl+Shift+M - Mobile View
-->

<!-- HTML Live Validation -->
<script>
// Real-time HTML validation
function validateHTML() {
    const html = document.documentElement.outerHTML;

    // Check for common issues
    const issues = [];

    // Missing alt attributes
    const images = document.querySelectorAll('img:not([alt])');
    if (images.length > 0) {
        issues.push(`${images.length} images missing alt attributes`);
    }

    // Missing form labels
    const inputs = document.querySelectorAll('input:not([aria-label]):not([aria-labelledby])');
    inputs.forEach(input => {
        const id = input.id;
        if (id && !document.querySelector(`label[for="${id}"]`)) {
            issues.push(`Input with id "${id}" has no associated label`);
        }
    });

    // Empty headings
    const emptyHeadings = document.querySelectorAll('h1:empty, h2:empty, h3:empty, h4:empty, h5:empty, h6:empty');
    if (emptyHeadings.length > 0) {
        issues.push(`${emptyHeadings.length} empty headings found`);
    }

    console.log('HTML Validation Issues:', issues);
    return issues;
}

// Run validation
validateHTML();
</script>

<!-- HTML Minification -->
<script>
function minifyHTML(html) {
    return html
        .replace(/\s+/g, ' ')  // Multiple spaces to single space
        .replace(/>\s+</g, '><')  // Remove spaces between tags
        .replace(/^\s+|\s+$/g, '');  // Trim whitespace
}

// Example usage
const originalHTML = `
    <div>
        <p>  Text content  </p>
        <span>   More text   </span>
    </div>
`;

const minified = minifyHTML(originalHTML);
console.log('Minified:', minified);
</script>

<!-- HTML Beautifier -->
<script>
function beautifyHTML(html) {
    let formatted = '';
    let indent = 0;
    const indentSize = 4;

    html.split('<').forEach((element, index) => {
        if (index === 0) {
            formatted += element;
            return;
        }

        const isClosingTag = element.startsWith('/');
        const isSelfClosing = element.endsWith('/>') ||
            ['br', 'img', 'input', 'hr', 'meta', 'link'].some(tag =>
                element.startsWith(tag + ' ') || element.startsWith(tag + '>'));

        if (isClosingTag) {
            indent -= indentSize;
        }

        formatted += '\n' + ' '.repeat(Math.max(0, indent)) + '<' + element;

        if (!isClosingTag && !isSelfClosing) {
            indent += indentSize;
        }
    });

    return formatted;
}
</script>
```

### Validation Tools

```html
<!-- W3C Markup Validator Integration -->
<script>
async function validateWithW3C(html) {
    const formData = new FormData();
    formData.append('fragment', html);
    formData.append('output', 'json');

    try {
        const response = await fetch('https://validator.w3.org/nu/', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        return result.messages;
    } catch (error) {
        console.error('Validation error:', error);
        return [];
    }
}

// Accessibility validation
function checkAccessibility() {
    const issues = [];

    // Check for missing alt text
    const imagesWithoutAlt = document.querySelectorAll('img:not([alt])');
    imagesWithoutAlt.forEach(img => {
        issues.push({
            type: 'error',
            element: img,
            message: 'Image missing alt attribute'
        });
    });

    // Check color contrast (simplified)
    const elements = document.querySelectorAll('*');
    elements.forEach(el => {
        const style = getComputedStyle(el);
        const bg = style.backgroundColor;
        const color = style.color;

        // Simple contrast check (would need more sophisticated calculation)
        if (bg !== 'rgba(0, 0, 0, 0)' && color !== 'rgba(0, 0, 0, 0)') {
            // Calculate contrast ratio here
        }
    });

    // Check heading hierarchy
    const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
    let lastLevel = 0;
    headings.forEach(heading => {
        const level = parseInt(heading.tagName.charAt(1));
        if (level > lastLevel + 1) {
            issues.push({
                type: 'warning',
                element: heading,
                message: `Heading level ${level} follows level ${lastLevel} - skipped levels`
            });
        }
        lastLevel = level;
    });

    return issues;
}

// SEO validation
function checkSEO() {
    const issues = [];

    // Check for title
    const title = document.querySelector('title');
    if (!title || title.textContent.length < 10) {
        issues.push('Title is missing or too short');
    }

    // Check for meta description
    const description = document.querySelector('meta[name="description"]');
    if (!description || description.content.length < 120) {
        issues.push('Meta description is missing or too short');
    }

    // Check for h1
    const h1 = document.querySelectorAll('h1');
    if (h1.length === 0) {
        issues.push('No H1 heading found');
    } else if (h1.length > 1) {
        issues.push('Multiple H1 headings found');
    }

    return issues;
}
</script>

<!-- Performance analysis -->
<script>
function analyzePerformance() {
    const metrics = {};

    // DOM metrics
    metrics.elementCount = document.querySelectorAll('*').length;
    metrics.scriptTags = document.querySelectorAll('script').length;
    metrics.stylesheetLinks = document.querySelectorAll('link[rel="stylesheet"]').length;
    metrics.images = document.querySelectorAll('img').length;

    // Image optimization check
    const largeImages = Array.from(document.images).filter(img => {
        return img.naturalWidth > 1920 || img.naturalHeight > 1080;
    });
    metrics.largeImages = largeImages.length;

    // External resources
    const externalResources = Array.from(document.querySelectorAll('script[src], link[href], img[src]'))
        .filter(el => {
            const url = el.src || el.href;
            return url && !url.startsWith(window.location.origin);
        });
    metrics.externalResources = externalResources.length;

    return metrics;
}

// Run all checks
function runAllChecks() {
    console.log('Accessibility Issues:', checkAccessibility());
    console.log('SEO Issues:', checkSEO());
    console.log('Performance Metrics:', analyzePerformance());
}

// Auto-run on page load
window.addEventListener('load', runAllChecks);
</script>
```

### Reference Resources

```html
<!-- HTML Entity Reference -->
<!--
Common HTML Entities:
&lt;    <    Less than
&gt;    >    Greater than
&amp;   &    Ampersand
&quot;  "    Quotation mark
&apos;  '    Apostrophe
&nbsp;       Non-breaking space
&copy;  ©    Copyright
&reg;   ®    Registered trademark
&trade; ™    Trademark
&mdash; —    Em dash
&ndash; –    En dash
&hellip; …   Horizontal ellipsis
-->

<!-- Quick Reference Card -->
<div id="html-reference" style="display: none;">
    <h3>HTML Quick Reference</h3>

    <h4>Document Structure</h4>
    <code>
        &lt;!DOCTYPE html&gt;<br>
        &lt;html lang="en"&gt;<br>
        &lt;head&gt;<br>
        &nbsp;&nbsp;&lt;meta charset="UTF-8"&gt;<br>
        &nbsp;&nbsp;&lt;title&gt;Page Title&lt;/title&gt;<br>
        &lt;/head&gt;<br>
        &lt;body&gt;<br>
        &nbsp;&nbsp;Content here<br>
        &lt;/body&gt;<br>
        &lt;/html&gt;
    </code>

    <h4>Common Elements</h4>
    <ul>
        <li><code>&lt;h1&gt; to &lt;h6&gt;</code> - Headings</li>
        <li><code>&lt;p&gt;</code> - Paragraph</li>
        <li><code>&lt;a href=""&gt;</code> - Link</li>
        <li><code>&lt;img src="" alt=""&gt;</code> - Image</li>
        <li><code>&lt;div&gt;</code> - Generic container</li>
        <li><code>&lt;span&gt;</code> - Inline container</li>
        <li><code>&lt;ul&gt;&lt;li&gt;</code> - Unordered list</li>
        <li><code>&lt;ol&gt;&lt;li&gt;</code> - Ordered list</li>
    </ul>

    <h4>Form Elements</h4>
    <ul>
        <li><code>&lt;form action="" method=""&gt;</code></li>
        <li><code>&lt;input type="text" name=""&gt;</code></li>
        <li><code>&lt;textarea name=""&gt;&lt;/textarea&gt;</code></li>
        <li><code>&lt;select&gt;&lt;option&gt;</code></li>
        <li><code>&lt;button type="submit"&gt;</code></li>
    </ul>

    <h4>Semantic Elements</h4>
    <ul>
        <li><code>&lt;header&gt;</code> - Page/section header</li>
        <li><code>&lt;nav&gt;</code> - Navigation</li>
        <li><code>&lt;main&gt;</code> - Main content</li>
        <li><code>&lt;article&gt;</code> - Standalone content</li>
        <li><code>&lt;section&gt;</code> - Thematic grouping</li>
        <li><code>&lt;aside&gt;</code> - Sidebar content</li>
        <li><code>&lt;footer&gt;</code> - Page/section footer</li>
    </ul>
</div>

<!-- Interactive examples -->
<script>
function showExample(type) {
    const examples = {
        table: `
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Age</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Alice</td>
            <td>30</td>
        </tr>
    </tbody>
</table>`,
        form: `
<form>
    <label for="name">Name:</label>
    <input type="text" id="name" name="name" required>

    <label for="email">Email:</label>
    <input type="email" id="email" name="email" required>

    <button type="submit">Submit</button>
</form>`,
        semantic: `
<article>
    <header>
        <h2>Article Title</h2>
        <time datetime="2024-03-15">March 15, 2024</time>
    </header>

    <section>
        <p>Article content goes here...</p>
    </section>

    <footer>
        <p>Author: John Doe</p>
    </footer>
</article>`
    };

    const output = document.getElementById('example-output');
    output.innerHTML = `<pre><code>${examples[type]}</code></pre>`;
}
</script>

<div>
    <button onclick="showExample('table')">Table Example</button>
    <button onclick="showExample('form')">Form Example</button>
    <button onclick="showExample('semantic')">Semantic Example</button>

    <div id="example-output"></div>
</div>
```