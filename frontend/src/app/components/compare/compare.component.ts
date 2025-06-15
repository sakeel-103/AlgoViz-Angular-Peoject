import { Component, AfterViewInit, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  FormsModule,
  ReactiveFormsModule,
  FormGroup,
  FormBuilder,
} from '@angular/forms';
import { NavbarComponent } from '../navbar/navbar.component';
import { Chart } from 'chart.js/auto';
import { Network, DataSet } from 'vis-network/standalone';

interface Graph {
  nodes: { id: number; label: string }[];
  edges: { from: number; to: number; weight?: number }[];
  isDirected?: boolean;
  isWeighted?: boolean;
}

interface PerformanceMetrics {
  averageCaseTime: number;
  worstCaseTime: number;
  spaceComplexity: number;
  qualityScore: number;
  iterationCount: number;
  theoreticalTime: string;
  theoreticalSpace: string;
}

interface AlgorithmResult {
  steps: string[];
  output: string;
  runtime: number;
  memory: number;
  metrics: PerformanceMetrics;
  visualSteps: {
    nodes: number[];
    edges: { from: number; to: number }[];
    description: string;
  }[];
  useCaseScore: {
    pathFinding: number;
    treeOptimization: number;
    memoryEfficiency: number;
    speedPriority: number;
    cycleDetection: number;
    topologicalSort: number;
  };
}

interface ComparisonMetrics {
  timeComplexityDiff: string;
  spaceComplexityDiff: string;
  qualityDiff: string;
  useCaseAnalysis: string;
  recommendations: string[];
  theoreticalComparison: string;
}

@Component({
  selector: 'app-compare',
  standalone: true,
  imports: [CommonModule, FormsModule, ReactiveFormsModule, NavbarComponent],
  templateUrl: './compare.component.html',
  styleUrls: ['./compare.component.css'],
})
export class ComparisonComponent implements AfterViewInit {
  @ViewChild('graphCanvas') graphCanvas!: ElementRef<HTMLDivElement>;
  @ViewChild('efficiencyChart') chartCanvas!: ElementRef<HTMLCanvasElement>;
  efficiencyChart: Chart | null = null;
  network: Network | null = null;
  graphForm: FormGroup;
  selectedAlgorithm1: string = '';
  selectedAlgorithm2: string = '';
  showComparison: boolean = false;
  errorMessage: string = '';
  comparisonResult: {
    algo1: AlgorithmResult;
    algo2: AlgorithmResult;
  } | null = null;
  availableAlgorithms: string[] = [
    'BFS Algorithm',
    'DFS Algorithm',
    "Prim's Algorithm",
    "Kruskal's Algorithm",
    "Dijkstra's Algorithm",
  ];

  predefinedGraphs: { name: string; graph: Graph }[] = [
    {
      name: 'Sparse Undirected',
      graph: {
        nodes: [
          { id: 1, label: '1' },
          { id: 2, label: '2' },
          { id: 3, label: '3' },
          { id: 4, label: '4' },
        ],
        edges: [
          { from: 1, to: 2, weight: 1 },
          { from: 2, to: 3, weight: 2 },
          { from: 3, to: 4, weight: 3 },
        ],
        isDirected: false,
        isWeighted: true,
      },
    },
    {
      name: 'Dense Undirected',
      graph: {
        nodes: [
          { id: 1, label: '1' },
          { id: 2, label: '2' },
          { id: 3, label: '3' },
          { id: 4, label: '4' },
        ],
        edges: [
          { from: 1, to: 2, weight: 1 },
          { from: 1, to: 3, weight: 4 },
          { from: 1, to: 4, weight: 3 },
          { from: 2, to: 3, weight: 2 },
          { from: 2, to: 4, weight: 5 },
          { from: 3, to: 4, weight: 1 },
        ],
        isDirected: false,
        isWeighted: true,
      },
    },
    {
      name: 'Directed Acyclic',
      graph: {
        nodes: [
          { id: 1, label: '1' },
          { id: 2, label: '2' },
          { id: 3, label: '3' },
          { id: 4, label: '4' },
        ],
        edges: [
          { from: 1, to: 2, weight: 1 },
          { from: 1, to: 3, weight: 2 },
          { from: 2, to: 4, weight: 3 },
          { from: 3, to: 4, weight: 2 },
        ],
        isDirected: true,
        isWeighted: true,
      },
    },
    {
      name: 'Connected Components',
      graph: {
        nodes: [
          { id: 1, label: '1' },
          { id: 2, label: '2' },
          { id: 3, label: '3' },
          { id: 4, label: '4' },
          { id: 5, label: '5' },
        ],
        edges: [
          { from: 1, to: 2, weight: 1 },
          { from: 3, to: 4, weight: 2 },
        ],
        isDirected: false,
        isWeighted: true,
      },
    },
  ];

  constructor(private fb: FormBuilder) {
    this.graphForm = this.fb.group({
      numNodes: [6],
      numEdges: [8],
      predefinedGraph: [''],
      graphType: ['undirected'],
      weighted: [true],
    });
  }

  ngAfterViewInit(): void {
    this.renderGraph(this.predefinedGraphs[0].graph);
  }

  renderGraph(graph: Graph): void {
    const container = this.graphCanvas?.nativeElement;
    if (!container) return;

    const nodes = new DataSet(
      graph.nodes.map((node) => ({
        id: node.id,
        label: node.label,
        color: '#6ac6ff',
      }))
    );

    const edgesWithId = graph.edges.map((edge, idx) => ({
      id: idx + 1,
      from: edge.from,
      to: edge.to,
      label: graph.isWeighted ? edge.weight?.toString() : '',
      color: '#cccccc',
      arrows: graph.isDirected ? 'to' : undefined,
    }));

    const edges = new DataSet(edgesWithId);
    const data = { nodes, edges };
    const options = {
      edges: {
        font: { size: 12, color: '#343434' },
        smooth: { enabled: true, type: 'continuous', roundness: 0.5 },
        arrows: { to: { enabled: graph.isDirected } },
      },
      nodes: {
        font: { size: 14, color: '#ffffff' },
        borderWidth: 2,
        shadow: true,
      },
      physics: {
        enabled: true,
        stabilization: {
          fit: true,
          iterations: 1000,
        },
      },
    };

    this.network = new Network(container, data, options);
  }

  loadPredefinedGraph(): void {
    const selectedGraphName = this.graphForm.get('predefinedGraph')?.value;
    const selectedGraph = this.predefinedGraphs.find(
      (g) => g.name === selectedGraphName
    )?.graph;
    if (selectedGraph) {
      this.graphForm.patchValue({
        numNodes: selectedGraph.nodes.length,
        numEdges: selectedGraph.edges.length,
        graphType: selectedGraph.isDirected ? 'directed' : 'undirected',
        weighted: selectedGraph.isWeighted,
      });
      this.renderGraph(selectedGraph);
    }
  }

  generateRandomGraph(numNodes: number, numEdges: number): Graph {
    const isDirected = this.graphForm.get('graphType')?.value === 'directed';
    const isWeighted = this.graphForm.get('weighted')?.value;
    const maxEdges = isDirected
      ? numNodes * (numNodes - 1)
      : (numNodes * (numNodes - 1)) / 2;

    if (numEdges > maxEdges) {
      this.errorMessage = `Number of edges cannot exceed ${maxEdges} for ${numNodes} nodes in ${
        isDirected ? 'directed' : 'undirected'
      } graph.`;
      throw new Error(this.errorMessage);
    }

    const nodes = Array.from({ length: numNodes }, (_, i) => ({
      id: i + 1,
      label: `${i + 1}`,
    }));

    const edges: { from: number; to: number; weight?: number }[] = [];
    const possibleEdges: { from: number; to: number }[] = [];

    for (let i = 1; i <= numNodes; i++) {
      for (let j = 1; j <= numNodes; j++) {
        if (i !== j && (isDirected || i < j)) {
          possibleEdges.push({ from: i, to: j });
        }
      }
    }

    for (let i = possibleEdges.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [possibleEdges[i], possibleEdges[j]] = [
        possibleEdges[j],
        possibleEdges[i],
      ];
    }

    for (let i = 0; i < numEdges; i++) {
      const edge = possibleEdges[i];
      const weight = isWeighted
        ? Math.floor(Math.random() * 10) + 1
        : undefined;
      edges.push({ from: edge.from, to: edge.to, weight });
    }

    return { nodes, edges, isDirected, isWeighted };
  }

  parseGraph(): Graph {
    const numNodes = Number(this.graphForm.get('numNodes')?.value) || 0;
    const numEdges = Number(this.graphForm.get('numEdges')?.value) || 0;

    if (numNodes < 1) {
      this.errorMessage = 'Number of nodes must be at least 1.';
      throw new Error(this.errorMessage);
    }

    try {
      return this.generateRandomGraph(numNodes, numEdges);
    } catch (error: any) {
      this.errorMessage = error.message;
      throw error;
    }
  }

  resetComparison(): void {
    this.showComparison = false;
    this.errorMessage = '';
    this.comparisonResult = null;
    if (this.efficiencyChart) {
      this.efficiencyChart.destroy();
      this.efficiencyChart = null;
    }
  }

  isValidComparison(algo1: string, algo2: string): boolean {
    const validPairs = [
      ['BFS Algorithm', 'DFS Algorithm'],
      ["Prim's Algorithm", "Kruskal's Algorithm"],
      ["Dijkstra's Algorithm", 'BFS Algorithm'],
    ];

    return validPairs.some(
      (pair) =>
        (pair[0] === algo1 && pair[1] === algo2) ||
        (pair[1] === algo1 && pair[0] === algo2)
    );
  }

  compareAlgorithms(): void {
    this.errorMessage = '';
    if (!this.selectedAlgorithm1 || !this.selectedAlgorithm2) {
      this.errorMessage = 'Please select two algorithms to compare.';
      return;
    }
    if (this.selectedAlgorithm1 === this.selectedAlgorithm2) {
      this.errorMessage = 'Please select two different algorithms.';
      return;
    }
    if (
      !this.isValidComparison(this.selectedAlgorithm1, this.selectedAlgorithm2)
    ) {
      this.errorMessage =
        "Invalid comparison. Valid pairs are: BFS vs DFS, Prim's vs Kruskal's, or Dijkstra's vs BFS";
      return;
    }

    try {
      const graph = this.parseGraph();
      this.renderGraph(graph);

      if (
        this.selectedAlgorithm1.includes('BFS') ||
        this.selectedAlgorithm1.includes('DFS') ||
        this.selectedAlgorithm1.includes('Dijkstra')
      ) {
        this.compareTraversalAlgorithms(graph);
      } else {
        this.compareMSTAlgorithms(graph);
      }

      this.showComparison = true;
    } catch (error) {
      return;
    }
  }

  // ============ comparison methods ============
  compareTraversalAlgorithms(graph: Graph): void {
    const algo1Result = this.runTraversalAlgorithm(
      this.selectedAlgorithm1,
      graph
    );
    const algo2Result = this.runTraversalAlgorithm(
      this.selectedAlgorithm2,
      graph
    );

    const metrics = this.calculateComparisonMetrics(
      algo1Result,
      algo2Result,
      graph
    );

    this.comparisonResult = {
      algo1: algo1Result,
      algo2: algo2Result,
    };

    this.renderDetailedEfficiencyChart(algo1Result, algo2Result);
  }

  runTraversalAlgorithm(algo: string, graph: Graph): AlgorithmResult {
    const steps: string[] = [];
    let output = '';
    let runtime = 0;
    let memory = 0;
    const visualSteps: AlgorithmResult['visualSteps'] = [];

    const adjList: { [key: number]: { node: number; weight: number }[] } = {};
    graph.nodes.forEach((node) => (adjList[node.id] = []));
    graph.edges.forEach((edge) => {
      adjList[edge.from].push({ node: edge.to, weight: edge.weight || 1 });
      if (!graph.isDirected) {
        adjList[edge.to].push({ node: edge.from, weight: edge.weight || 1 });
      }
    });

    const visited: Set<number> = new Set();
    const result: number[] = [];
    const startNode = graph.nodes[0].id;

    if (algo === 'BFS Algorithm') {
      const queue: number[] = [startNode];
      visited.add(startNode);
      steps.push(`Starting BFS from node ${startNode}`);
      runtime += 2;

      while (queue.length > 0) {
        const node = queue.shift()!;
        result.push(node);
        steps.push(`Visiting node ${node}`);
        runtime += 3;

        for (const neighbor of adjList[node]) {
          if (!visited.has(neighbor.node)) {
            visited.add(neighbor.node);
            queue.push(neighbor.node);
            steps.push(`Adding node ${neighbor.node} to queue`);
            runtime += 4;
            memory = Math.max(memory, queue.length);
          }
        }
      }
    } else if (algo === 'DFS Algorithm') {
      const stack: number[] = [startNode];
      visited.add(startNode);
      steps.push(`Starting DFS from node ${startNode}`);
      runtime += 2;

      while (stack.length > 0) {
        const node = stack.pop()!;
        result.push(node);
        steps.push(`Visiting node ${node}`);
        runtime += 3;

        for (const neighbor of adjList[node]) {
          if (!visited.has(neighbor.node)) {
            visited.add(neighbor.node);
            stack.push(neighbor.node);
            steps.push(`Pushing node ${neighbor.node} to stack`);
            runtime += 4;
            memory = Math.max(memory, stack.length);
          }
        }
      }
    } else if (algo === "Dijkstra's Algorithm") {
      const distances: { [key: number]: number } = {};
      const previous: { [key: number]: number | null } = {};
      const priorityQueue: { node: number; distance: number }[] = [];

      graph.nodes.forEach((node) => {
        distances[node.id] = node.id === startNode ? 0 : Infinity;
        previous[node.id] = null;
      });

      priorityQueue.push({ node: startNode, distance: 0 });
      steps.push(`Initializing Dijkstra's from node ${startNode}`);
      runtime += graph.nodes.length * 2;

      while (priorityQueue.length > 0) {
        priorityQueue.sort((a, b) => a.distance - b.distance);
        const { node: current, distance } = priorityQueue.shift()!;

        if (distance > distances[current]) continue;

        steps.push(`Processing node ${current} with distance ${distance}`);
        runtime += 5;

        for (const neighbor of adjList[current]) {
          const newDistance = distances[current] + neighbor.weight;
          if (newDistance < distances[neighbor.node]) {
            distances[neighbor.node] = newDistance;
            previous[neighbor.node] = current;
            priorityQueue.push({ node: neighbor.node, distance: newDistance });
            steps.push(
              `Updating distance for node ${neighbor.node} to ${newDistance}`
            );
            runtime += 8;
          }
        }
        memory = Math.max(memory, priorityQueue.length);
      }

      output =
        `Shortest paths from node ${startNode}:\n` +
        Object.entries(distances)
          .map(
            ([node, dist]) =>
              `Node ${node}: ${dist === Infinity ? 'Unreachable' : dist}`
          )
          .join('\n');
    }

    if (algo !== "Dijkstra's Algorithm") {
      output = `Traversal Order: ${result.join(' -> ')}`;
    }

    const metrics: PerformanceMetrics = {
      averageCaseTime: runtime,
      worstCaseTime: runtime * Math.log(graph.nodes.length),
      spaceComplexity: memory,
      qualityScore: this.calculateQualityScore(steps, graph),
      iterationCount: steps.length,
      theoreticalTime:
        algo === "Dijkstra's Algorithm" ? 'O(V + E log V)' : 'O(V + E)',
      theoreticalSpace: algo === "Dijkstra's Algorithm" ? 'O(V)' : 'O(V)',
    };

    const useCaseScore = {
      pathFinding:
        algo === "Dijkstra's Algorithm"
          ? 1.0
          : algo === 'BFS Algorithm'
          ? 0.95
          : 0.6,
      treeOptimization: algo === 'DFS Algorithm' ? 0.85 : 0.65,
      memoryEfficiency: algo === 'DFS Algorithm' ? 0.9 : 0.7,
      speedPriority: algo === 'BFS Algorithm' ? 0.85 : 0.75,
      cycleDetection: algo === 'DFS Algorithm' ? 0.95 : 0.5,
      topologicalSort: algo === 'DFS Algorithm' ? 0.95 : 0.2,
    };

    return {
      steps,
      output,
      runtime,
      memory,
      metrics,
      visualSteps,
      useCaseScore,
    };
  }

  compareMSTAlgorithms(graph: Graph): void {
    const algo1Result = this.runMSTAlgorithm(this.selectedAlgorithm1, graph);
    const algo2Result = this.runMSTAlgorithm(this.selectedAlgorithm2, graph);

    const metrics = this.calculateComparisonMetrics(
      algo1Result,
      algo2Result,
      graph
    );

    this.comparisonResult = {
      algo1: algo1Result,
      algo2: algo2Result,
    };

    this.renderDetailedEfficiencyChart(algo1Result, algo2Result);
  }

  runMSTAlgorithm(algo: string, graph: Graph): AlgorithmResult {
    const steps: string[] = [];
    let output = '';
    let runtime = 0;
    let memory = 0;
    const visualSteps: AlgorithmResult['visualSteps'] = [];

    if (algo === "Prim's Algorithm") {
      const nodes = graph.nodes.map((n) => n.id);
      const edges = graph.edges;
      const visited: Set<number> = new Set();
      const mstEdges: { from: number; to: number; weight: number }[] = [];
      const key: { [key: number]: number } = {};
      const parent: { [key: number]: number } = {};

      nodes.forEach((node) => {
        key[node] = Infinity;
        parent[node] = -1;
      });

      const startNode = nodes[0];
      key[startNode] = 0;
      steps.push(`Starting Prim's from node ${startNode}`);
      runtime += nodes.length * 2;

      while (visited.size < nodes.length) {
        let minKey = Infinity;
        let u = -1;
        for (const node of nodes) {
          if (!visited.has(node) && key[node] < minKey) {
            minKey = key[node];
            u = node;
            runtime += 3;
          }
        }

        if (u === -1) break;
        visited.add(u);
        steps.push(`Adding node ${u} to MST (key=${key[u]})`);
        runtime += 5;

        for (const edge of edges) {
          const v = edge.from === u ? edge.to : edge.to === u ? edge.from : -1;
          if (v !== -1 && !visited.has(v)) {
            if (edge.weight! < key[v]) {
              key[v] = edge.weight!;
              parent[v] = u;
              steps.push(`Updating key for node ${v} to ${edge.weight}`);
              runtime += 8;
            }
          }
        }
        memory = Math.max(memory, nodes.length + edges.length);
      }

      for (const node of nodes) {
        if (parent[node] !== -1) {
          mstEdges.push({ from: parent[node], to: node, weight: key[node] });
        }
      }
      const totalWeight = mstEdges.reduce((sum, e) => sum + e.weight, 0);
      output = `MST Edges: ${mstEdges
        .map((e) => `(${e.from}-${e.to}: ${e.weight})`)
        .join(', ')}\nTotal Weight: ${totalWeight}`;
    } else {
      const edges = [...graph.edges].sort(
        (a, b) => (a.weight || 0) - (b.weight || 0)
      );
      const parent: { [key: number]: number } = {};
      const rank: { [key: number]: number } = {};

      const find = (x: number): number => {
        if (!parent[x]) parent[x] = x;
        if (parent[x] !== x) parent[x] = find(parent[x]);
        return parent[x];
      };

      const union = (x: number, y: number) => {
        const px = find(x),
          py = find(y);
        if (px === py) return;
        if (!rank[px]) rank[px] = 0;
        if (!rank[py]) rank[py] = 0;
        if (rank[px] < rank[py]) parent[px] = py;
        else if (rank[px] > rank[py]) parent[py] = px;
        else {
          parent[py] = px;
          rank[px]++;
        }
      };

      const mstEdges: { from: number; to: number; weight: number }[] = [];
      steps.push(`Starting Kruskal's with ${edges.length} edges`);
      runtime += edges.length * Math.log(edges.length);

      for (const edge of edges) {
        const u = edge.from,
          v = edge.to;
        if (find(u) !== find(v)) {
          union(u, v);
          mstEdges.push({ from: u, to: v, weight: edge.weight! });
          steps.push(`Adding edge (${u}-${v}: ${edge.weight}) to MST`);
          runtime += 5;
        }
        memory = Math.max(memory, Object.keys(parent).length);
      }

      const totalWeight = mstEdges.reduce((sum, e) => sum + e.weight, 0);
      output = `MST Edges: ${mstEdges
        .map((e) => `(${e.from}-${e.to}: ${e.weight})`)
        .join(', ')}\nTotal Weight: ${totalWeight}`;
    }

    const metrics: PerformanceMetrics = {
      averageCaseTime: runtime,
      worstCaseTime: runtime * Math.log(graph.nodes.length),
      spaceComplexity: memory,
      qualityScore: this.calculateQualityScore(steps, graph),
      iterationCount: steps.length,
      theoreticalTime:
        algo === "Prim's Algorithm" ? 'O(E + V log V)' : 'O(E log E)',
      theoreticalSpace: algo === "Prim's Algorithm" ? 'O(V + E)' : 'O(E)',
    };

    const useCaseScore = {
      pathFinding: 0.4,
      treeOptimization: algo === "Prim's Algorithm" ? 0.95 : 0.85,
      memoryEfficiency: algo === "Kruskal's Algorithm" ? 0.9 : 0.7,
      speedPriority: algo === "Prim's Algorithm" ? 0.85 : 0.75,
      cycleDetection: 0.6,
      topologicalSort: 0.1,
    };

    return {
      steps,
      output,
      runtime,
      memory,
      metrics,
      visualSteps,
      useCaseScore,
    };
  }

  calculateComparisonMetrics(
    algo1Result: AlgorithmResult,
    algo2Result: AlgorithmResult,
    graph: Graph
  ): ComparisonMetrics {
    return {
      timeComplexityDiff: this.analyzeTimeComplexity(
        algo1Result.metrics,
        algo2Result.metrics
      ),
      spaceComplexityDiff: this.analyzeSpaceComplexity(
        algo1Result.metrics,
        algo2Result.metrics
      ),
      qualityDiff: this.analyzeQualityMetrics(
        algo1Result.metrics,
        algo2Result.metrics
      ),
      useCaseAnalysis: this.generateUseCaseAnalysis(
        algo1Result.useCaseScore,
        algo2Result.useCaseScore
      ),
      recommendations: this.generateRecommendations(
        algo1Result,
        algo2Result,
        graph
      ),
      theoreticalComparison: this.generateTheoreticalComparison(
        algo1Result.metrics,
        algo2Result.metrics
      ),
    };
  }

  analyzeTimeComplexity(
    metrics1: PerformanceMetrics,
    metrics2: PerformanceMetrics
  ): string {
    const avgDiff = metrics1.averageCaseTime - metrics2.averageCaseTime;
    const worstDiff = metrics1.worstCaseTime - metrics2.worstCaseTime;

    return `Time Complexity: 
      Avg case: ${metrics1.averageCaseTime}ms vs ${
      metrics2.averageCaseTime
    }ms (${avgDiff < 0 ? 'Algo 1 faster' : 'Algo 2 faster'})
      Worst case: ${metrics1.worstCaseTime}ms vs ${metrics2.worstCaseTime}ms (${
      worstDiff < 0 ? 'Algo 1 better' : 'Algo 2 better'
    })`;
  }

  analyzeSpaceComplexity(
    metrics1: PerformanceMetrics,
    metrics2: PerformanceMetrics
  ): string {
    const spaceDiff = metrics1.spaceComplexity - metrics2.spaceComplexity;
    return `Space Usage: ${metrics1.spaceComplexity} vs ${
      metrics2.spaceComplexity
    } units (${
      spaceDiff < 0 ? 'Algo 1 more efficient' : 'Algo 2 more efficient'
    })`;
  }

  analyzeQualityMetrics(
    metrics1: PerformanceMetrics,
    metrics2: PerformanceMetrics
  ): string {
    const qualityDiff = metrics1.qualityScore - metrics2.qualityScore;
    return `Solution Quality: ${metrics1.qualityScore.toFixed(
      2
    )} vs ${metrics2.qualityScore.toFixed(2)} (${
      qualityDiff < 0 ? 'Algo 2 better' : 'Algo 1 better'
    })`;
  }

  generateUseCaseAnalysis(
    score1: AlgorithmResult['useCaseScore'],
    score2: AlgorithmResult['useCaseScore']
  ): string {
    const analysis = [];

    if (score1.pathFinding !== score2.pathFinding) {
      analysis.push(
        `Path finding: ${
          score1.pathFinding > score2.pathFinding
            ? 'Algorithm 1 better'
            : 'Algorithm 2 better'
        }`
      );
    }

    if (score1.treeOptimization !== score2.treeOptimization) {
      analysis.push(
        `Tree optimization: ${
          score1.treeOptimization > score2.treeOptimization
            ? 'Algorithm 1 better'
            : 'Algorithm 2 better'
        }`
      );
    }

    if (score1.memoryEfficiency !== score2.memoryEfficiency) {
      analysis.push(
        `Memory efficiency: ${
          score1.memoryEfficiency > score2.memoryEfficiency
            ? 'Algorithm 1 better'
            : 'Algorithm 2 better'
        }`
      );
    }

    if (score1.cycleDetection !== score2.cycleDetection) {
      analysis.push(
        `Cycle detection: ${
          score1.cycleDetection > score2.cycleDetection
            ? 'Algorithm 1 better'
            : 'Algorithm 2 better'
        }`
      );
    }

    return analysis.join(' | ');
  }

  generateRecommendations(
    algo1Result: AlgorithmResult,
    algo2Result: AlgorithmResult,
    graph: Graph
  ): string[] {
    const recommendations: string[] = [];
    const density = this.calculateGraphDensity(graph);
    if (algo1Result.runtime < algo2Result.runtime) {
      recommendations.push(`For speed, prefer ${this.selectedAlgorithm1}`);
    } else {
      recommendations.push(`For speed, prefer ${this.selectedAlgorithm2}`);
    }

    if (algo1Result.memory < algo2Result.memory) {
      recommendations.push(
        `For memory efficiency, prefer ${this.selectedAlgorithm1}`
      );
    } else {
      recommendations.push(
        `For memory efficiency, prefer ${this.selectedAlgorithm2}`
      );
    }
    if (
      this.selectedAlgorithm1.includes('BFS') ||
      this.selectedAlgorithm1.includes('DFS')
    ) {
      if (density < 0.3) {
        recommendations.push(
          'For sparse graphs, DFS is typically more memory efficient'
        );
      } else {
        recommendations.push(
          'For dense graphs, BFS is typically better for shortest paths'
        );
      }

      if (graph.isDirected) {
        recommendations.push(
          'For directed graphs, DFS is better for cycle detection and topological sorting'
        );
      }
    } else {
      if (density < 0.3) {
        recommendations.push(
          "For sparse graphs, Kruskal's is typically more efficient"
        );
      } else {
        recommendations.push(
          "For dense graphs, Prim's is typically more efficient with a priority queue"
        );
      }
    }

    return recommendations;
  }

  generateTheoreticalComparison(
    metrics1: PerformanceMetrics,
    metrics2: PerformanceMetrics
  ): string {
    return `
      <strong>Theoretical Comparison:</strong>
      <p>Algorithm 1: Time: ${metrics1.theoreticalTime}, Space: ${metrics1.theoreticalSpace}</p>
      <p>Algorithm 2: Time: ${metrics2.theoreticalTime}, Space: ${metrics2.theoreticalSpace}</p>
    `;
  }

  calculateGraphDensity(graph: Graph): number {
    const nodeCount = graph.nodes.length;
    const edgeCount = graph.edges.length;
    return edgeCount / ((nodeCount * (nodeCount - 1)) / 2);
  }

  calculateQualityScore(steps: string[], graph: Graph): number {
    const uniqueNodesVisited = new Set(
      steps
        .filter((step) => step.startsWith('Visiting'))
        .map((step) => parseInt(step.split(' ')[2]))
    ).size;

    const coverageScore = (uniqueNodesVisited / graph.nodes.length) * 50;
    const efficiencyScore = 50 / (steps.length / graph.nodes.length);

    return Math.min(coverageScore + efficiencyScore, 100);
  }

  renderDetailedEfficiencyChart(
    algo1Result: AlgorithmResult,
    algo2Result: AlgorithmResult
  ): void {
    const ctx = this.chartCanvas?.nativeElement;
    if (!ctx) return;

    if (this.efficiencyChart) {
      this.efficiencyChart.destroy();
    }

    // Prepare data for the bar chart
    const maxRuntime = Math.max(algo1Result.runtime, algo2Result.runtime);
    const maxMemory = Math.max(algo1Result.memory, algo2Result.memory);
    const maxSpace = Math.max(
      algo1Result.metrics.spaceComplexity,
      algo2Result.metrics.spaceComplexity
    );

    // Normalize values to a scale of 0-300 (as seen in the image)
    const scale = 300 / Math.max(maxRuntime, maxMemory, maxSpace);

    this.efficiencyChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Time Complexity', 'Space Complexity', 'Memory Usage'],
        datasets: [
          {
            label: this.selectedAlgorithm1,
            data: [
              algo1Result.runtime * scale,
              algo1Result.metrics.spaceComplexity * scale,
              algo1Result.memory * scale,
            ],
            backgroundColor: '#ff6b6b', // Red for Algorithm 1 (matches image)
            borderColor: '#ff6b6b',
            borderWidth: 1,
          },
          {
            label: this.selectedAlgorithm2,
            data: [
              algo2Result.runtime * scale,
              algo2Result.metrics.spaceComplexity * scale,
              algo2Result.memory * scale,
            ],
            backgroundColor: '#4ecdc4', // Teal for Algorithm 2 (matches image)
            borderColor: '#4ecdc4',
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'top' },
          tooltip: { enabled: true },
          title: {
            display: true,
            text: 'Efficiency Comparison Chart',
          },
        },
        scales: {
          x: {
            title: {
              display: true,
              text: 'Metrics',
            },
          },
          y: {
            title: {
              display: true,
              text: 'Relative Performance',
            },
            beginAtZero: true,
            max: 300, // Set max to 300 as per the image
          },
        },
      },
    });
  }

  goBack(): void {
    window.history.back();
  }
}
