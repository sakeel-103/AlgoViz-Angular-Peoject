import { CommonModule } from '@angular/common';
import {
  Component,
  ViewEncapsulation,
  Input,
  ViewChild,
  ElementRef,
  OnChanges,
  SimpleChanges,
  OnInit,
  AfterViewInit,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NavbarComponent } from '../navbar/navbar.component';

@Component({
  selector: 'app-graph-canvas-wrapper',
  standalone: true,
  template: `
    <div class="canvas-container">
      <canvas #graphCanvas width="500" height="400"></canvas>
    </div>
  `,
  styleUrls: ['./dfs-page.component.css'],
})
export class GraphCanvasWrapperComponent implements OnChanges, AfterViewInit {
  @Input() graph: number[][] = [];
  @Input() dfsEdges: { u: number; v: number }[] = [];
  @Input() traversedEdges: { u: number; v: number }[] = [];
  @Input() selectedNode: number | null = null;
  @Input() stackNodes: number[] | null = null;
  @Input() processedNodes: number[] | null = null;
  @Input() processingNode: number | null = null;
  @Input() isDirected: boolean = false;

  @ViewChild('graphCanvas', { static: false })
  canvas!: ElementRef<HTMLCanvasElement>;
  ctx: CanvasRenderingContext2D | null = null;

  ngAfterViewInit(): void {
    if (this.canvas) {
      this.ctx = this.canvas.nativeElement.getContext('2d');
      if (this.graph.length > 0 && this.ctx) {
        this.drawGraph();
      }
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (this.canvas && this.graph.length > 0) {
      if (!this.ctx) {
        this.ctx = this.canvas.nativeElement.getContext('2d');
      }
      if (this.ctx) {
        this.drawGraph();
      } else {
        console.error('Failed to get 2D context');
      }
    }
  }

  drawGraph(): void {
    if (!this.ctx || this.graph.length === 0) {
      return;
    }

    const ctx = this.ctx;
    const width = this.canvas.nativeElement.width;
    const height = this.canvas.nativeElement.height;

    ctx.clearRect(0, 0, width, height);

    const radius = Math.max(12, 20 - this.graph.length / 4);
    const positions: { x: number; y: number }[] = new Array(this.graph.length);

    const levels: number[] = new Array(this.graph.length).fill(-1);
    const parents: (number | null)[] = new Array(this.graph.length).fill(null);
    const children: number[][] = new Array(this.graph.length)
      .fill(0)
      .map(() => []);

    // ==================== Build parent and child relationships ===================
    for (let u = 0; u < this.graph.length; u++) {
      for (let v = 0; v < this.graph.length; v++) {
        if (this.graph[u][v] > 0) {
          children[u].push(v);
          if (this.isDirected || !parents[v]) {
            parents[v] = u;
          }
        }
      }
    }

    const assignLevels = (node: number, level: number) => {
      levels[node] = level;
      for (const child of children[node]) {
        assignLevels(child, level + 1);
      }
    };
    assignLevels(0, 0);

    const maxLevel = Math.max(...levels);
    const nodesPerLevel: number[][] = new Array(maxLevel + 1)
      .fill(0)
      .map(() => []);
    for (let i = 0; i < this.graph.length; i++) {
      if (levels[i] >= 0) {
        nodesPerLevel[levels[i]].push(i);
      }
    }

    // ============== Assign positions: spread nodes horizontally within each level ============
    const verticalSpacing = height / (maxLevel + 2);
    for (let level = 0; level <= maxLevel; level++) {
      const nodes = nodesPerLevel[level];
      const horizontalSpacing = width / (nodes.length + 1);
      nodes.forEach((node, idx) => {
        positions[node] = {
          x: (idx + 1) * horizontalSpacing,
          y: (level + 1) * verticalSpacing,
        };
      });
    }

    // ==============  Draw edges =========================
    for (let u = 0; u < this.graph.length; u++) {
      for (let v = 0; v < this.graph.length; v++) {
        if (this.graph[u][v] > 0 && (this.isDirected || u < v)) {
          const isDFSEdge = this.dfsEdges.some(
            (edge) =>
              (edge.u === u && edge.v === v) ||
              (!this.isDirected && edge.u === v && edge.v === u)
          );

          const isTraversed = this.traversedEdges.some(
            (edge) =>
              (edge.u === u && edge.v === v) ||
              (!this.isDirected && edge.u === v && edge.v === u)
          );

          ctx.beginPath();
          ctx.moveTo(positions[u].x, positions[u].y);

          if (this.isDirected) {
            const angle = Math.atan2(
              positions[v].y - positions[u].y,
              positions[v].x - positions[u].x
            );
            const endX = positions[v].x - radius * Math.cos(angle);
            const endY = positions[v].y - radius * Math.sin(angle);

            ctx.lineTo(endX, endY);
            ctx.strokeStyle = isDFSEdge || isTraversed ? '#00cc00' : '#7f8c8d';
            ctx.lineWidth = isDFSEdge || isTraversed ? 2.5 : 1.5;
            ctx.stroke();

            ctx.beginPath();
            ctx.moveTo(endX, endY);
            ctx.lineTo(
              endX - 10 * Math.cos(angle - Math.PI / 6),
              endY - 10 * Math.sin(angle - Math.PI / 6)
            );
            ctx.lineTo(
              endX - 10 * Math.cos(angle + Math.PI / 6),
              endY - 10 * Math.sin(angle + Math.PI / 6)
            );
            ctx.closePath();
            ctx.fillStyle = isDFSEdge || isTraversed ? '#00cc00' : '#7f8c8d';
            ctx.fill();
          } else {
            ctx.lineTo(positions[v].x, positions[v].y);
            ctx.strokeStyle = isDFSEdge || isTraversed ? '#00cc00' : '#7f8c8d';
            ctx.lineWidth = isDFSEdge || isTraversed ? 2.5 : 1.5;
            ctx.stroke();
          }
        }
      }
    }

    // ================ Draw nodes ==============
    for (let i = 0; i < this.graph.length; i++) {
      ctx.beginPath();
      ctx.arc(positions[i].x, positions[i].y, radius, 0, 2 * Math.PI);
      if (this.processingNode === i && this.stackNodes !== null) {
        ctx.fillStyle = '#ffd700';
      } else if (
        this.stackNodes &&
        this.stackNodes.includes(i) &&
        this.stackNodes !== null
      ) {
        ctx.fillStyle = '#4682b4';
      } else if (
        this.processedNodes &&
        this.processedNodes.includes(i) &&
        this.processedNodes !== null
      ) {
        ctx.fillStyle = '#ff4500';
      } else {
        ctx.fillStyle = '#f7f1f1';
      }

      ctx.fill();
      ctx.strokeStyle = '#2c3e50';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.font = '14px Arial';
      ctx.fillStyle = '#000000';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(i.toString(), positions[i].x, positions[i].y);
    }
  }
}

@Component({
  selector: 'app-dfs-page',
  standalone: true,
  templateUrl: './dfs-page.component.html',
  styleUrls: ['./dfs-page.component.css'],
  imports: [
    FormsModule,
    CommonModule,
    NavbarComponent,
    GraphCanvasWrapperComponent,
  ],
  encapsulation: ViewEncapsulation.None,
})
export class DfsPageComponent implements OnInit {
  numNodes: number = 7;
  startNode: number = 0;
  graphType: 'undirected' | 'directed' = 'directed';
  graph: number[][] = [];
  dfsEdges: { u: number; v: number }[] = [];
  traversedEdges: { u: number; v: number }[] = [];
  steps: {
    node: number;
    stack: number[];
    edge?: { u: number; v: number };
    processed: number[];
    explanation: string;
  }[] = [];
  currentStep: number = 0;
  isPlaying: boolean = false;
  selectedNode: number | null = null;
  processingNode: number | null = null;
  stack: number[] = [];
  processed: number[] = [];
  explanation: string = '';
  isValid: boolean = true;
  animationTimer: any = null;

  ngOnInit(): void {
    this.validateInputs();
    this.generateGraph();
  }

  validateInputs(): void {
    if (this.numNodes < 5) {
      this.numNodes = 5;
    } else if (this.numNodes > 15) {
      this.numNodes = 15;
    }
    if (this.startNode < 0) {
      this.startNode = 0;
    } else if (this.startNode >= this.numNodes) {
      this.startNode = this.numNodes - 1;
    }
    this.isValid = true;
  }

  generateGraph(): void {
    this.validateInputs();
    if (!this.isValid) return;

    if (this.isPlaying) {
      this.handlePlayPause();
    }

    this.resetAnimation();

    this.graph = Array.from({ length: this.numNodes }, () =>
      Array(this.numNodes).fill(0)
    );

    this.generateTree();
    this.runDFS();
  }

  generateTree(): void {
    const visited = new Set<number>([0]);
    const nodes = Array.from({ length: this.numNodes }, (_, i) => i);
    nodes.sort(() => Math.random() - 0.5);

    for (let i = 1; i < this.numNodes; i++) {
      const possibleParents = Array.from(visited);
      const parent =
        possibleParents[Math.floor(Math.random() * possibleParents.length)];
      if (this.graphType === 'undirected') {
        this.graph[parent][nodes[i]] = 1;
        this.graph[nodes[i]][parent] = 1;
      } else {
        this.graph[parent][nodes[i]] = 1;
      }
      visited.add(nodes[i]);
    }

    console.log('Adjacency Matrix:', this.graph);
  }

  runDFS(): void {
    this.dfsEdges = [];
    this.traversedEdges = [];
    this.steps = [];
    this.stack = [];
    this.processed = [];

    const visited = new Set<number>();
    this.stack.push(this.startNode);

    this.steps.push({
      node: this.startNode,
      stack: [...this.stack],
      processed: [...this.processed],
      explanation: `Starting DFS from node ${this.startNode}. Pushed to stack.`,
    });

    while (this.stack.length > 0) {
      const currentNode = this.stack.pop()!;

      if (!visited.has(currentNode)) {
        visited.add(currentNode);
        this.processed.push(currentNode);

        this.steps.push({
          node: currentNode,
          stack: [...this.stack],
          processed: [...this.processed],
          explanation: `Visiting node ${currentNode}. Marked as processed.`,
        });

        const children: number[] = [];
        for (let v = 0; v < this.numNodes; v++) {
          if (this.graph[currentNode][v] > 0 && !visited.has(v)) {
            children.push(v);
          }
        }

        for (let i = children.length - 1; i >= 0; i--) {
          const child = children[i];
          this.stack.push(child);
          const edge = { u: currentNode, v: child };
          this.dfsEdges.push(edge);

          this.steps.push({
            node: child,
            stack: [...this.stack],
            processed: [...this.processed],
            edge,
            explanation: `Discovered node ${child} from ${currentNode}. Pushed to stack.`,
          });
        }

        if (children.length === 0) {
          this.steps.push({
            node: currentNode,
            stack: [...this.stack],
            processed: [...this.processed],
            explanation: `Node ${currentNode} has no unvisited children. Backtracking.`,
          });
        }
      }
    }

    this.steps.push({
      node: this.startNode,
      stack: [],
      processed: [...this.processed],
      explanation: `DFS complete. All ${this.numNodes} nodes visited.`,
    });

    this.resetAnimation();
  }

  resetAnimation(): void {
    if (this.animationTimer) {
      clearTimeout(this.animationTimer);
      this.animationTimer = null;
    }
    this.currentStep = 0;
    this.selectedNode = null;
    this.processingNode = null;
    this.stack = [];
    this.processed = [];
    this.traversedEdges = [];
    this.explanation = '';
    this.isPlaying = false;
  }

  playAnimation(): void {
    if (this.currentStep < this.steps.length && this.graph.length > 0) {
      const step = this.steps[this.currentStep];
      this.processingNode = step.node;
      this.selectedNode = step.node;
      this.stack = [...step.stack];
      this.processed = [...step.processed];
      this.explanation = step.explanation;

      if (step.edge) {
        this.traversedEdges.push(step.edge);
      }

      this.currentStep++;
    } else {
      this.isPlaying = false;
    }
  }

  handlePlayPause(): void {
    this.isPlaying = !this.isPlaying;
    if (this.isPlaying && this.graph.length > 0) {
      if (this.currentStep >= this.steps.length) {
        this.resetAnimation();
      }
      this.autoPlay();
    } else {
      if (this.animationTimer) {
        clearTimeout(this.animationTimer);
        this.animationTimer = null;
      }
    }
  }

  autoPlay(): void {
    if (this.isPlaying && this.currentStep < this.steps.length) {
      this.playAnimation();
      this.animationTimer = setTimeout(() => {
        this.autoPlay();
      }, 1000);
    } else {
      this.isPlaying = false;
    }
  }

  goBack(): void {
    window.history.back();
  }
}
