//! Native COSMIC subscription profile selector.
mod app;
mod i18n;

fn main() -> cosmic::iced::Result {
    i18n::init();
    let flags = app::Flags::from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let size = flags.window_size();
    let settings = cosmic::app::Settings::default();
    let settings = match flags.theme_override() {
        Some(theme) => settings.theme(theme),
        None => settings,
    };
    cosmic::app::run::<app::App>(
        settings.size(size).size_limits(
            cosmic::iced::advanced::layout::Limits::NONE
                .min_width(520.0)
                .min_height(520.0),
        ),
        flags,
    )
}
