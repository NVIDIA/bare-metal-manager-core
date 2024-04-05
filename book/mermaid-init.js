// For the list of supported configs, reference
// https://github.com/mermaid-js/mermaid/blob/master/packages/mermaid/src/config.type.ts

// For certain diagrams, we want them to be scrollable.
// TODO: Check whether this could be a css flag on the diagram itself
var useMaxWidth = true
if (window.location.pathname.includes('schema.html')) {
    useMaxWidth = false;
}

mermaid.initialize({
    startOnLoad:true,
    flowchart: { useMaxWidth: useMaxWidth },
    sequence: { useMaxWidth: useMaxWidth },
    theme: 'neutral'
});
