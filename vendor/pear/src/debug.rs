use std::collections::HashMap;
use inlinable_string::InlinableString;

use crate::input::{Show, Input, Debugger, ParserInfo};
use crate::macros::is_parse_debug;

type Index = usize;

struct Tree<T> {
    // All of the nodes in the tree live in this vector.
    nodes: Vec<T>,
    // Maps from an index (`parent`) index `nodes` to a set of indexes in
    // `nodes` corresponding to the children of `key`.
    children: HashMap<Index, Vec<Index>>,
    // This "tree" keeps track of which parent children are currently being
    // pushed to. A `push` adds to this stack while a `pop` removes from this
    // stack. If the stack is empty, the root is being pushed to.
    stack: Vec<Index>
}

impl<T> Tree<T> {
    fn new() -> Tree<T> {
        Tree {
            nodes: vec![],
            children: HashMap::new(),
            stack: Vec::with_capacity(8)
        }
    }

    fn push(&mut self, node: T) -> Index {
        // Add the node to the tree and get its index.
        self.nodes.push(node);
        let index = self.nodes.len() - 1;

        // If the stack indicates we have a parent, add to its children.
        if !self.stack.is_empty() {
            let parent = self.stack[self.stack.len() - 1];
            self.children.entry(parent).or_insert(vec![]).push(index);
        }

        // Make this the new parent.
        self.stack.push(index);
        index
    }

    fn pop_level(&mut self) -> Option<Index> {
        self.stack.pop()
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn get(&self, index: Index) -> &T {
        &self.nodes[index]
    }

    fn get_mut(&mut self, index: Index) -> &mut T {
        &mut self.nodes[index]
    }

    fn get_children(&self, index: Index) -> &[Index] {
        match self.children.get(&index) {
            Some(children) => &children[..],
            None => &[]
        }
    }
}

impl Tree<Info> {
    fn debug_print(&self, sibling_map: &mut Vec<bool>, node: Index) {
        let parent_count = sibling_map.len();
        for (i, &has_siblings) in sibling_map.iter().enumerate() {
            if i < parent_count - 1 {
                match has_siblings {
                    true => print!(" │   "),
                    false => print!("     ")
                }
            } else {
                match has_siblings {
                    true => print!(" ├── "),
                    false => print!(" └── ")
                }
            }
        }

        let info = self.get(node);
        let success = match info.success {
            Some(true) => " ✓",
            Some(false) => " ✗",
            None => ""
        };

        #[cfg(feature = "color")]
        let color = match info.success {
            Some(true) => ::yansi::Color::Green,
            Some(false) => ::yansi::Color::Red,
            None => ::yansi::Color::Unset,
        };

        #[cfg(feature = "color")]
        println!("{} ({})",
            color.paint(format!("{}{}", info.parser.name, success)),
            info.context);

        #[cfg(not(feature = "color"))]
        println!("{}{} ({})", info.name, success, info.context);

        let children = self.get_children(node);
        let num_children = children.len();
        for (i, &child) in children.iter().enumerate() {
            let have_siblings = i != (num_children - 1);
            sibling_map.push(have_siblings);
            self.debug_print(sibling_map, child);
            sibling_map.pop();
        }
    }
}

struct Info {
    parser: ParserInfo,
    context: InlinableString,
    success: Option<bool>,
}

impl Info {
    fn new(parser: ParserInfo) -> Self {
        Info { parser, context: iformat!(), success: None }
    }
}

pub struct TreeDebugger {
    tree: Tree<Info>,
}

impl TreeDebugger {
    pub fn new() -> Self {
        Self { tree: Tree::new() }
    }
}

impl<I: Input> Debugger<I> for TreeDebugger {
    fn on_entry(&mut self, p: &ParserInfo) {
        if !((p.raw && is_parse_debug!("full")) || (!p.raw && is_parse_debug!())) {
            return;
        }

        self.tree.push(Info::new(*p));
    }

    fn on_exit(&mut self, p: &ParserInfo, ok: bool, ctxt: I::Context) {
        if !((p.raw && is_parse_debug!("full")) || (!p.raw && is_parse_debug!())) {
            return;
        }

        let index = self.tree.pop_level();
        if let Some(last_node) = index {
            let last = self.tree.get_mut(last_node);
            last.success = Some(ok);
            last.context = iformat!("{}", &ctxt as &dyn Show);
        }

        // We've reached the end. Print the whole thing and clear the tree.
        if let Some(0) = index {
            #[cfg(feature = "color")] {
                if cfg!(windows) && !::yansi::Paint::enable_windows_ascii() {
                    ::yansi::Paint::disable();
                }
            }

            self.tree.debug_print(&mut vec![], 0);
            self.tree.clear();
        }
    }
}
