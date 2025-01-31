# Order-the-Fuzz

## Overview

**Order-the-Fuzz** is a tool designed to assist security researchers in analyzing binary executables and identifying the most effective entry points for fuzz testing. By leveraging the **angr** binary analysis framework, the tool constructs a **call graph**, prioritizes root functions based on configurable metrics, and outputs an optimized fuzzing order.

## Features

- **Automated Call Graph Analysis:**  
  - Identifies root functions in a binary program.
  - Supports analysis from both binaries and pre-generated GML call graph files.
  
- **Fuzzing Prioritization:**  
  - Uses memory operation and function count metrics to rank root functions.
  - Customizable weighting for different analysis goals.

- **Visualization and Export:**  
  - Call graph visualization with function relationships.
  - Outputs fuzzing orders for further processing.

- **Configurable Analysis:**  
  - Adjustable parameters via a `config.json` file.
  - Flexible reordering logic to optimize function coverage.

---

## Fuzzing Order Calculation

The order in which functions are prioritized for fuzzing is determined by a **customizable metric formula**. This formula combines two metrics, each weighted according to the user-defined parameters in the `config.json` file:

**Formula**:  
`Metric Value = (weight_1 * metric_1) + (weight_2 * metric_2)`

Where:  
- **`metric_1`**: The **number of memory-related calls** reachable from a root function's subtree (e.g., calls to functions like `malloc`, `calloc`, `memcpy`).  
- **`metric_2`**: The **total number of functions** reachable in the root function's subtree.  
- **`weight_1`**: A user-defined weight emphasizing the importance of memory-related calls (`memory_call_count_weight`).  
- **`weight_2`**: A user-defined weight emphasizing the importance of function counts (`function_count_weight`).  

### Example Calculation

If you configure the following weights in `config.json`:

```json
"memory_call_count_weight": 2,
"function_count_weight": 1
```

And for a root function:
- `metric_1` = 10 (memory-related calls)
- `metric_2` = 20 (functions in the subtree)

The metric value for the root function would be:

```
Metric Value = (2 * 10) + (1 * 20) = 40
```

### Why This Matters

By adjusting the weights (`weight_1` and `weight_2`), you can tailor the fuzzing order to focus on:
- **Memory-intensive paths**: Prioritize paths with more memory operations (e.g., to uncover buffer overflows).  
- **Broader coverage**: Focus on root functions that reach a higher number of subfunctions.  

This flexibility ensures the tool can adapt to your specific fuzzing goals, whether you are targeting memory safety vulnerabilities or aiming for maximal function coverage.

---

## Reordering Logic

During fuzzing, **Order-the-Fuzz** can reorder root functions to maximize overall coverage. Specifically, after generating an initial fuzzing order based on the metric (memory calls vs. function count), the tool checks how many new subfunctions each root function would cover compared to those already covered by previously analyzed roots. The list is then reordered to prioritize roots that introduce the most uncovered functions.

- **Why Reorder?**  
  Ensures each successive root function contributes new or less-covered paths and encourages more comprehensive testing in fewer iterations.

- **How Often?**  
  The frequency and number of reorder passes is controlled by the `reorder_amount` field in `config.json`.  
  - `-1` attempts reordering until the sequence stabilizes (or indefinitely).  
  - Any other integer value (e.g., `0`, `1`, `2`) limits how many rounds of reordering occur.
  
---

## How it works

1.	Load the binary (or GML file) into angr.
2.	Generate or import a call graph.
3.	(Optionally) Filter out irrelevant or sub_N functions.
4.	Compute custom metrics for each root function.
5.	Rank root functions based on metric weights.
6.	(Optionally) Reorder to refine coverage.
7.	Output final fuzzing order + call graph visualizations.

---

## Installation

### Prerequisites

Ensure you have the following installed:

- **Python 3.8+**
- **pip3** (for package management)
- Dependencies listed in `requirements.txt`

### Installation Steps

1. Clone this repository:

   \`\`\`
   git clone https://github.com/flurinB/order-the-fuzz.git \
   cd order-the-fuzz
   \`\`\`

2. Install the required dependencies:

   \`\`\`
   pip3 install -r requirements.txt
   \`\`\`

---

## Usage



### 1. Configure the Tool

Edit the `config.json` file to set your analysis parameters:

| Key                         | Type    | Default | Description                                                      |
|-----------------------------|---------|---------|------------------------------------------------------------------|
| `use_gml_file`             | bool    | false   | If true, load the call graph from the specified GML file         |
| `path_to_binary`           | string  | ""      | Path to the binary to be analyzed                                |
| `path_to_gml_file`         | string  | ""      | Path to the GML file (if `use_gml_file` is true)                 |
| `memory_functions`         | list    | […]     | Functions considered for memory call counting                    |
| `output_plot_path`         | string  | "…"     | Where to save the .png visualization                             |
| `output_graph_path`        | string  | "…"     | Where to save the final GML call graph                           |
| `reorder_amount`           | int     | -1      | How many times to reorder (-1 means reorder indefinitely)        |
| `memory_call_count_weight` | float   | 1.0     | Weight for memory-related calls metric                           |
| `function_count_weight`    | float   | 1.0     | Weight for function count metric                                 |
| `remove_sub_n_functions`   | bool    | false   | Whether to remove `sub_XXX` functions from analysis              |

---

### 2. Removing `sub_N` Functions from Analysis

If `sub_N` functions are irrelevant to your analysis, the tool includes a feature to filter them out from the call graph and subsequent analyses. This can be configured in the `config.json` file:

```json
{
  "remove_sub_n_functions": true
}
```

When this option is set to `true`:
- Functions with placeholder names like `sub_N` will be excluded from the call graph.
- These functions will not contribute to metrics or fuzzing order calculations.

#### How This Helps

- **Reduces Noise**: Filtering out `sub_N` functions ensures that only meaningful functions are analyzed.
- **Focus on Relevant Functions**: Eliminates unnecessary functions, allowing you to concentrate on those most relevant to fuzzing or vulnerability discovery.
- **Improves Performance**: By reducing the size of the call graph, the analysis process can be faster and more efficient.

---


### 3. Run the Analysis

Once the configuration is set, run the tool using:

\`\`\`
python3 main.py
\`\`\`

---

### 4. Output

After execution, the following output files will be generated:

- **\`fuzzing_order.txt\`** - The initial prioritized order of functions to fuzz.
- **Call Graph Visualization** - A `.png` image if specified in the configuration.
- **Call Graph File** - A `.gml` representation of the call graph.

---

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Open a pull request.

---

## License

This project is licensed under the MIT License. See the \`LICENSE\` file for details.

---

## Contact

For any questions or suggestions, please contact:  
**[Flurin Baumann]** - [flurin.baumann@gmail.com]  
GitHub: [https://github.com/flurinB](https://github.com/flurinB)
