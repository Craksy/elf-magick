pub struct Table {
    pub header: String,
    pub labels: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

struct Struct {}

impl Table {
    pub fn build(&self) -> String {
        //Get the minimum width for each column
        let col_widths: Vec<usize> = self
            .labels
            .iter()
            .enumerate()
            .map(|(i, l)| {
                l.len()
                    .max(self.rows.iter().max_by_key(|r| r[i].len()).unwrap()[i].len())
                    + 4
            })
            .collect();

        // Build the header/title row
        let header = format!(
            "[1;34m{:^1$}[0m",
            self.header,
            col_widths.iter().sum::<usize>() + self.labels.len() - 1
        );

        // Build the top and bottom row, as well the separator rows around title and labels
        let [top, head_sep, label_sep, bot] = [('━', '━'), ('━', '┯'), ('─', '┼'), ('━', '┻')]
            .map(|(fc, jc)| make_separator(fc, jc, &col_widths));

        // Build the row with labels
        let label_row = self
            .labels
            .iter()
            .zip(&col_widths)
            .map(|(l, w)| format!("[1;35m{:^1$}[0m", l, w))
            .collect::<Vec<String>>()
            .join("│");

        // Build the actual table rows. One text row per table row.
        let rows = self
            .rows
            .to_owned()
            .into_iter()
            .map(|r| {
                r.iter()
                    .zip(col_widths.iter())
                    .map(|(v, w)| format!("{:^1$}", v, w))
                    .collect::<Vec<String>>()
                    .join("│")
            })
            .map(|r| format!("┃{}┃", r))
            .collect::<Vec<String>>()
            .join("\n");

        //put it all together
        format!(
            "
┏{}┓
┃{}┃
┣{}┫
┃{}┃
┠{}┨
{}
┗{}┛
",
            top, header, head_sep, label_row, label_sep, rows, bot
        )
    }
}

fn make_separator(fillchar: char, joinchar: char, col_spans: &Vec<usize>) -> String {
    col_spans
        .iter()
        .map(|w| fillchar.to_string().repeat(*w))
        .collect::<Vec<String>>()
        .join(&joinchar.to_string())
}
