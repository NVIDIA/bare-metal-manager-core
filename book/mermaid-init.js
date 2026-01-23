// For the list of supported configs, reference
// https://github.com/mermaid-js/mermaid/blob/master/packages/mermaid/src/config.type.ts

// For certain diagrams, we want them to be scrollable.
// TODO: Check whether this could be a css flag on the diagram itself
var useMaxWidth = true
if (window.location.pathname.includes('schema.html')) {
    useMaxWidth = false;
}

mermaid.initialize({
    startOnLoad: false,
    flowchart: { useMaxWidth: useMaxWidth },
    sequence: { useMaxWidth: useMaxWidth },
    theme: 'neutral'
});

async function drawDiagrams() {
    //  Convert Mermaid text to SVGs first
    await mermaid.run({
        querySelector: '.mermaid',
    });

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
