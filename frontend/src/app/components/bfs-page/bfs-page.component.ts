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
  styleUrls: ['./bfs-page.component.css'],
})
export class GraphCanvasWrapperComponent implements OnChanges, AfterViewInit {
  @Input() graph: number[][] = [];
  @Input() bfsEdges: { u: number; v: number }[] = [];
  @Input() traversedEdges: { u: number; v: number }[] = [];
  @Input() selectedNode: number | null = null;
  @Input() queueNodes: number[] | null = null;
  @Input() processedNodes: number[] | null = null;
  @Input() processingNode: number | null = null;
  @Input() isDirected: boolean = false;
  @Input() showTraversal: boolean = true;

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

    const radius = Math.max(10, 18 - this.graph.length / 5);
    const positions: { x: number; y: number }[] = new Array(this.graph.length);

    const levels: number[] = new Array(this.graph.length).fill(-1);
    const parents: (number | null)[] = new Array(this.graph.length).fill(null);
    const children: number[][] = new Array(this.graph.length)
      .fill(0)
      .map(() => []);

    // ===============Build parent and child relationships==============
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

    // Assign levels using BFS from node 0
    const assignLevels = () => {
      const queue: number[] = [0];
      levels[0] = 0;
      while (queue.length > 0) {
        const node = queue.shift()!;
        for (const child of children[node]) {
          if (levels[child] === -1) {
            levels[child] = levels[node] + 1;
            queue.push(child);
          }
        }
      }
    };
    assignLevels();

    const maxLevel = Math.max(...levels);
    const nodesPerLevel: number[][] = new Array(maxLevel + 1)
      .fill(0)
      .map(() => []);
    for (let i = 0; i < this.graph.length; i++) {
      if (levels[i] >= 0) {
        nodesPerLevel[levels[i]].push(i);
      }
    }

    const verticalSpacing = height / (maxLevel + 2);
    for (let level = 0; level <= maxLevel; level++) {
      const nodes = nodesPerLevel[level];
      const levelWidth = Math.min(width * 0.9, nodes.length * 60);
      const horizontalSpacing =
        nodes.length > 1 ? levelWidth / (nodes.length - 1) : width;
      const offsetX = (width - levelWidth) / 2;

      nodes.forEach((node, idx) => {
        positions[node] = {
          x: offsetX + idx * horizontalSpacing,
          y: (level + 1) * verticalSpacing,
        };
      });
    }

    // ==================Draw edges=============================
    for (let u = 0; u < this.graph.length; u++) {
      for (let v = 0; v < this.graph.length; v++) {
        if (this.graph[u][v] > 0 && (this.isDirected || u < v)) {
          const isBFSEdge = this.bfsEdges.some(
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
            ctx.strokeStyle =
              this.showTraversal && (isBFSEdge || isTraversed)
                ? '#00cc00'
                : '#7f8c8d';
            ctx.lineWidth =
              this.showTraversal && (isBFSEdge || isTraversed) ? 2.5 : 1.5;
            ctx.stroke();

            if (this.showTraversal) {
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
              ctx.fillStyle = isBFSEdge || isTraversed ? '#00cc00' : '#7f8c8d';
              ctx.fill();
            }
          } else {
            ctx.lineTo(positions[v].x, positions[v].y);
            ctx.strokeStyle =
              this.showTraversal && (isBFSEdge || isTraversed)
                ? '#00cc00'
                : '#7f8c8d';
            ctx.lineWidth =
              this.showTraversal && (isBFSEdge || isTraversed) ? 2.5 : 1.5;
            ctx.stroke();
          }
        }
      }
    }

    // ====================== Draw nodes ========================================
    for (let i = 0; i < this.graph.length; i++) {
      ctx.beginPath();
      ctx.arc(positions[i].x, positions[i].y, radius, 0, 2 * Math.PI);

      if (this.showTraversal) {
        if (this.processingNode === i && this.queueNodes !== null) {
          ctx.fillStyle = '#ffd700';
        } else if (
          this.queueNodes &&
          this.queueNodes.includes(i) &&
          this.queueNodes !== null
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
  selector: 'app-bfs-page',
  standalone: true,
  templateUrl: './bfs-page.component.html',
  styleUrls: ['./bfs-page.component.css'],
  imports: [
    FormsModule,
    CommonModule,
    NavbarComponent,
    GraphCanvasWrapperComponent,
  ],
  encapsulation: ViewEncapsulation.None,
})
export class BfsPageComponent implements OnInit {
  numNodes: number = 7;
  startNode: number = 0;
  graphType: 'undirected' | 'directed' = 'directed';
  graph: number[][] = [];
  bfsEdges: { u: number; v: number }[] = [];
  traversedEdges: { u: number; v: number }[] = [];
  steps: {
    node: number;
    queue: number[];
    edge?: { u: number; v: number };
    processed: number[];
    explanation: string;
  }[] = [];
  currentStep: number = 0;
  isPlaying: boolean = false;
  selectedNode: number | null = null;
  processingNode: number | null = null;
  queue: number[] = [];
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
    this.runBFS();
  }

  generateTree(): void {
    const visited = new Set<number>([this.startNode]);
    const nodes = Array.from({ length: this.numNodes }, (_, i) => i).filter(
      (i) => i !== this.startNode
    );
    nodes.sort(() => Math.random() - 0.5);

    const childrenCount: number[] = new Array(this.numNodes).fill(0);
    const maxChildren = 3;

    for (const node of nodes) {
      const possibleParents = Array.from(visited).filter(
        (p) => childrenCount[p] < maxChildren
      );
      if (possibleParents.length === 0) {
        possibleParents.push(...visited);
      }
      const parent =
        possibleParents[Math.floor(Math.random() * possibleParents.length)];

      if (this.graphType === 'undirected') {
        this.graph[parent][node] = 1;
        this.graph[node][parent] = 1;
      } else {
        this.graph[parent][node] = 1;
      }

      visited.add(node);
      childrenCount[parent]++;
    }

    console.log('Tree Adjacency Matrix:', this.graph);
  }

  runBFS(): void {
    this.bfsEdges = [];
    this.traversedEdges = [];
    this.steps = [];
    this.queue = [];
    this.processed = [];

    const visited = new Set<number>();
    this.queue.push(this.startNode);

    this.steps.push({
      node: this.startNode,
      queue: [...this.queue],
      processed: [...this.processed],
      explanation: `Starting BFS from node ${this.startNode}. Added to queue.`,
    });

    while (this.queue.length > 0) {
      const currentNode = this.queue.shift()!;

      if (!visited.has(currentNode)) {
        visited.add(currentNode);
        this.processed.push(currentNode);

        this.steps.push({
          node: currentNode,
          queue: [...this.queue],
          processed: [...this.processed],
          explanation: `Visiting node ${currentNode}. Marked as processed.`,
        });

        const children: number[] = [];
        for (let v = 0; v < this.numNodes; v++) {
          if (this.graph[currentNode][v] > 0 && !visited.has(v)) {
            children.push(v);
          }
        }

        children.sort((a, b) => a - b);

        for (const child of children) {
          this.queue.push(child);
          const edge = { u: currentNode, v: child };
          this.bfsEdges.push(edge);

          this.steps.push({
            node: child,
            queue: [...this.queue],
            processed: [...this.processed],
            edge,
            explanation: `Discovered node ${child} from ${currentNode}. Added to queue.`,
          });
        }

        if (children.length === 0) {
          this.steps.push({
            node: currentNode,
            queue: [...this.queue],
            processed: [...this.processed],
            explanation: `Node ${currentNode} has no unvisited children. Moving to next node in queue.`,
          });
        }
      }
    }

    this.steps.push({
      node: this.startNode,
      queue: [],
      processed: [...this.processed],
      explanation: `BFS complete. All ${this.numNodes} nodes visited.`,
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
    this.queue = [];
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
      this.queue = [...step.queue];
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
