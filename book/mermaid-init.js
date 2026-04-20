// For the list of supported configs, reference
// https://github.com/mermaid-js/mermaid/blob/master/packages/mermaid/src/config.type.ts

// For certain diagrams, we want them to be scrollable.
var useMaxWidth = true
var isSchemaPage = window.location.pathname.includes('schema.html');
if (isSchemaPage) {
    useMaxWidth = false;
}

// erDiagram config (defaults are fairly roomy; tighten on schema page only).
var erConfig = { useMaxWidth: useMaxWidth };
if (isSchemaPage) {
    Object.assign(erConfig, {
        fontSize: 10,
        diagramPadding: 10,
        entityPadding: 8,
        minEntityWidth: 78,
        minEntityHeight: 56,
        nodeSpacing: 95,
        rankSpacing: 50,
    });
}

mermaid.initialize({
    startOnLoad: false,
    flowchart: { useMaxWidth: useMaxWidth },
    sequence: { useMaxWidth: useMaxWidth },
    // erDiagram uses `er`, not flowchart — without this, huge ER diagrams shrink to column width.
    er: erConfig,
    theme: 'neutral'
});

async function drawDiagrams() {
    //  Convert Mermaid text to SVGs first
    await mermaid.run({
        querySelector: '.mermaid',
    });

    // Large schema ER: wrap in .schema-er-scroll so overflow is local to a
    // viewport-sized box — horizontal scrollbars stay at the bottom of that
    // box instead of only at the bottom of the whole page.
    if (isSchemaPage) {
        const elems = document.getElementsByClassName('mermaid');
        for (const elem of elems) {
            if (elem.parentElement && elem.parentElement.classList.contains('schema-er-scroll')) {
                continue;
            }
            const wrap = document.createElement('div');
            wrap.className = 'schema-er-scroll';
            elem.parentNode.insertBefore(wrap, elem);
            wrap.appendChild(elem);
        }
    }

    // If a "mermaid-zoom" container is around the element,
    // enable zooming via svgPanZoom
    let elems = document.getElementsByClassName("mermaid");
    for (elem of elems) {
        if (!elem.parentElement.classList.contains("mermaid-zoom")) {
            continue;
        }

        elem.style.width = "100%";
        elem.style.height = "100%";

        let svgElem = elem.firstChild;
        svgElem.style.maxWidth = null;
        svgElem.style.width = "100%";
        svgElem.style.height = "100%";
        
        var panZoomElem = svgPanZoom(svgElem, {
            panEnabled: true,
            zoomEnabled: true,
            controlIconsEnabled: true,
            fit: true,
            center: true
        })
    }
}

document.addEventListener("DOMContentLoaded", async function(event){
    await drawDiagrams();
});
