# Binary Fuzzing Entry Point Analyzer

## Overview

The **Binary Fuzzing Entry Point Analyzer** is a tool designed to assist security researchers in analyzing binary executables and identifying the most effective entry points for fuzz testing. By leveraging the **angr** binary analysis framework, the tool constructs a **call graph**, prioritizes root functions based on configurable metrics, and outputs an optimized fuzzing order.

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
  - Flexible reordering logic to maximize function coverage.

---

## Installation

### Prerequisites

Ensure you have the following installed:

- **Python 3.8+**
- **pip3** (for package management)
- Dependencies listed in `requirements.txt`

### Installation Steps

1. Clone this repository:

   \`\`\`bash
   git clone https://github.com/yourusername/binary-fuzzing-entry-analyzer.git
   cd binary-fuzzing-entry-analyzer
   \`\`\`

2. Install the required dependencies:

   \`\`\`bash
   pip3 install -r requirements.txt
   \`\`\`

---

## Usage

### 1. Configure the Tool

Edit the `config.json` file to set your analysis parameters:

\`\`\`json
{
  "use_gml_file": false,
  "path_to_binary": "path/to/your/binary",
  "path_to_gml_file": "path/to/callgraph.gml",
  "memory_functions": ["malloc", "calloc", "memcpy"],
  "output_plot_path": "output/callgraph.png",
  "output_graph_path": "output/final_callgraph",
  "reorder_amount": -1,
  "memory_call_count_weight": 1,
  "function_count_weight": 1
}
\`\`\`

---

### 2. Run the Analysis

Once the configuration is set, run the tool using:

\`\`\`bash
python3 main.py
\`\`\`

---

### 3. Output

After execution, the following output files will be generated:

- **\`fuzzing_order.txt\`** - The initial prioritized order of functions to fuzz.
- **\`fuzzing_order_reordered.txt\`** - The reordered fuzzing order after optimization.
- **Call Graph Visualization** - A `.png` image if specified in the configuration.
- **Call Graph File** - A `.gml` representation of the call graph.

---

## Advanced Options

### Reordering the Fuzzing Order

You can refine the fuzzing order using:

\`\`\`python
order = reorder_n_times(keys_list, reorder_amount)
save_fuzzing_order_to_file(sorted_by_value_ascending, "fuzzing_order_reordered.txt")
\`\`\`

---

## Troubleshooting

- **Incorrect function names?**  
  Ensure the binary is compiled with symbols or use debugging versions.

- **Performance issues?**  
  Consider adjusting the \`auto_load_libs\` setting when initializing the binary to avoid unnecessary dependency analysis.

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
**[Your Name]** - [Your Email]  
GitHub: [https://github.com/yourusername](https://github.com/yourusername)
