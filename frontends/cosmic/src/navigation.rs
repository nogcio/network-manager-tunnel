//! Native primary selection, independent of HTTP, NM operations and their outcomes.
use super::Page;
use cosmic::iced::widget::scrollable::AbsoluteOffset;
use cosmic::widget::nav_bar;

pub(super) struct Navigation {
    pub model: nav_bar::Model,
    connections: nav_bar::Id,
    subscriptions: nav_bar::Id,
    connections_scroll: AbsoluteOffset,
    subscriptions_scroll: AbsoluteOffset,
}

impl Default for Navigation {
    fn default() -> Self {
        let mut model = nav_bar::Model::default();
        let connections = model.insert().text(Page::Connections.title()).id();
        let subscriptions = model.insert().text(Page::Import.title()).id();
        model.activate(connections);
        Self {
            model,
            connections,
            subscriptions,
            connections_scroll: AbsoluteOffset::default(),
            subscriptions_scroll: AbsoluteOffset::default(),
        }
    }
}

impl Navigation {
    pub fn page(&self, id: nav_bar::Id) -> Option<Page> {
        if id == self.connections {
            Some(Page::Connections)
        } else if id == self.subscriptions {
            Some(Page::Import)
        } else {
            None
        }
    }

    pub fn select(&mut self, page: Page) {
        self.model.activate(match page {
            Page::Connections => self.connections,
            Page::Import => self.subscriptions,
        });
    }

    pub fn remember_scroll(&mut self, page: Page, offset: AbsoluteOffset) {
        *match page {
            Page::Connections => &mut self.connections_scroll,
            Page::Import => &mut self.subscriptions_scroll,
        } = offset;
    }

    pub fn scroll(&self, page: Page) -> AbsoluteOffset {
        match page {
            Page::Connections => self.connections_scroll,
            Page::Import => self.subscriptions_scroll,
        }
    }
}
