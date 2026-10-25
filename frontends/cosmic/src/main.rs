//! Native COSMIC subscription profile selector.
mod app;

fn main() -> cosmic::iced::Result {
    let flags = app::Flags::from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let size = flags.window_size();
    let theme = flags.theme();
    cosmic::app::run::<app::App>(
        cosmic::app::Settings::default()
            .theme(theme)
            .size(size)
            .size_limits(
                cosmic::iced::advanced::layout::Limits::NONE
                    .min_width(520.0)
                    .min_height(520.0),
            ),
        flags,
    )
}
