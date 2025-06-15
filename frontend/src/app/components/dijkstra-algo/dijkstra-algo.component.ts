import { CommonModule } from '@angular/common';
import {
  Component,
  ViewEncapsulation,
  Input,
  ViewChild,
  ElementRef,
  OnChanges,
  SimpleChanges,
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
  styleUrls: ['./dijkstra-algo.component.css'],
})
export class GraphCanvasWrapperComponent implements OnChanges {
  @Input() graph: number[][] = [];
  @Input() path: number[] = [];
  @Input() showWeights: boolean = true;
  @Input() selectedNode: number | null = null;
  @Input() isDirected: boolean = false;
  @ViewChild('graphCanvas', { static: true })
  canvas!: ElementRef<HTMLCanvasElement>;
  ctx: CanvasRenderingContext2D | null = null;

  ngOnChanges(changes: SimpleChanges): void {
    if (this.canvas) {
      this.ctx = this.canvas.nativeElement.getContext('2d');
      if (this.ctx) {
        this.drawGraph();
      }
    }
  }

  drawGraph(): void {
    if (!this.ctx) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, 500, 400);
    const radius = 20;
    const centerX = 250;
    const centerY = 200;
    const angleStep = (2 * Math.PI) / this.graph.length;
    const positions: { x: number; y: number }[] = [];

    // ========== Calculate node positions ===
    for (let i = 0; i < this.graph.length; i++) {
      const x = centerX + 150 * Math.cos(i * angleStep);
      const y = centerY + 150 * Math.sin(i * angleStep);
      positions.push({ x, y });
    }

    // =========  Draw thes edges ======
    for (let u = 0; u < this.graph.length; u++) {
      for (let v = 0; v < this.graph.length; v++) {
        if (this.graph[u][v] > 0) {
          if (!this.isDirected && u > v) continue;
          const isBidirectional =
            this.isDirected && this.graph[u][v] > 0 && this.graph[v][u] > 0;

          // === here it determines if this edge is a part of the shortest path or not
          const isPathEdge = this.isEdgeInPath(u, v);
          ctx.beginPath();
          ctx.moveTo(positions[u].x, positions[u].y);
          const dx = positions[v].x - positions[u].x;
          const dy = positions[v].y - positions[u].y;
          const len = Math.sqrt(dx * dx + dy * dy);

          // =====  If it is directed graph then draw the arrow
          if (this.isDirected) {
            const udx = dx / len;
            const udy = dy / len;
            const endX = positions[v].x - udx * radius;
            const endY = positions[v].y - udy * radius;

            ctx.lineTo(endX, endY);
          } else {
            ctx.lineTo(positions[v].x, positions[v].y);
          }

          // ====  here colors decides the edge based on if it's in the path
          ctx.strokeStyle = isPathEdge
            ? 'green'
            : isBidirectional
            ? '#9c27b0'
            : 'black';
          ctx.lineWidth = isPathEdge ? 3 : isBidirectional ? 2 : 1;
          ctx.stroke();

          // ====  Arrowhead for directed graphs
          if (this.isDirected) {
            this.drawArrowhead(
              ctx,
              positions[u].x,
              positions[u].y,
              positions[v].x,
              positions[v].y,
              radius,
              isPathEdge ? 'green' : 'black'
            );
          }

          // =====  It defines edge weight
          if (this.showWeights) {
            const midX = (positions[u].x + positions[v].x) / 2;
            const midY = (positions[u].y + positions[v].y) / 2;
            let offsetX = 0;
            let offsetY = 0;
            if (this.isDirected && isBidirectional) {
              const perpX = (-(positions[v].y - positions[u].y) / len) * 10;
              const perpY = ((positions[v].x - positions[u].x) / len) * 10;
              offsetX = perpX;
              offsetY = perpY;
            }

            ctx.fillStyle = isPathEdge ? 'green' : 'black';
            ctx.font = '16px Arial';
            ctx.fillText(
              this.graph[u][v].toString(),
              midX + offsetX,
              midY + offsetY
            );
          }
        }
      }
    }

    // ==== Now here it draw the nodes
    for (let i = 0; i < this.graph.length; i++) {
      ctx.beginPath();
      ctx.arc(positions[i].x, positions[i].y, radius, 0, 2 * Math.PI);

      if (this.path.length > 0 && i === this.path[0]) {
        ctx.fillStyle = '#8bc34a';
      } else if (
        this.path.length > 0 &&
        i === this.path[this.path.length - 1]
      ) {
        ctx.fillStyle = '#ff9800';
      } else if (this.selectedNode === i) {
        ctx.fillStyle = '#81d4fa';
      } else if (this.path.includes(i)) {
        ctx.fillStyle = '#e6f7ff';
      } else {
        ctx.fillStyle = 'white';
      }

      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = 'black';
      ctx.fillText(i.toString(), positions[i].x - 5, positions[i].y + 5);
    }
  }

  // ======== for drawing arrowhead ========
  drawArrowhead(
    ctx: CanvasRenderingContext2D,
    fromX: number,
    fromY: number,
    toX: number,
    toY: number,
    radius: number,
    color: string
  ): void {
    const dx = toX - fromX;
    const dy = toY - fromY;
    const len = Math.sqrt(dx * dx + dy * dy);
    const udx = dx / len;
    const udy = dy / len;
    const arrowX = toX - udx * radius;
    const arrowY = toY - udy * radius;
    const perpX = -udy;
    const perpY = udx;
    ctx.beginPath();
    ctx.moveTo(arrowX, arrowY);
    ctx.lineTo(arrowX - 10 * udx + 6 * perpX, arrowY - 10 * udy + 6 * perpY);
    ctx.lineTo(arrowX - 10 * udx - 6 * perpX, arrowY - 10 * udy - 6 * perpY);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
  }

  // ========= checking if the edge is in the path or not =======
  isEdgeInPath(u: number, v: number): boolean {
    if (this.path.length <= 1) return false;

    for (let i = 0; i < this.path.length - 1; i++) {
      if (
        (this.path[i] === u && this.path[i + 1] === v) ||
        (!this.isDirected && this.path[i] === v && this.path[i + 1] === u)
      ) {
        return true;
      }
    }
    return false;
  }
}

@Component({
  selector: 'app-dijkstra-algo',
  standalone: true,
  templateUrl: './dijkstra-algo.component.html',
  styleUrls: ['./dijkstra-algo.component.css'],
  imports: [
    FormsModule,
    CommonModule,
    NavbarComponent,
    GraphCanvasWrapperComponent,
  ],
  encapsulation: ViewEncapsulation.None,
})
export class DijkstraAlgoComponent {
  numNodes: number = 6;
  initialNode: number = 0;
  destinationNode: number = 3;
  graph: number[][] = [];
  path: number[] = [];
  steps: { node: number; explanation: string }[] = [];
  currentStep: number = 0;
  isPlaying: boolean = false;
  selectedNode: number | null = null;
  explanation: string = '';
  showWeights: boolean = true;
  isDirected: boolean = false;
  nodesVisited: number[] = [];
  pathDescription: string = '';

  constructor() {
    this.generateGraph();
  }

  // ======= This function is used to generate the graph =======
  generateGraph(): void {
    if (this.numNodes < 6 || this.numNodes > 10) {
      alert('Please enter a number of nodes between 6 and 10.');
      return;
    }

    if (this.initialNode < 0 || this.initialNode >= this.numNodes) {
      alert(`Please select a source node between 0 and ${this.numNodes - 1}.`);
      return;
    }

    if (this.destinationNode < 0 || this.destinationNode >= this.numNodes) {
      alert(
        `Please select a destination node between 0 and ${this.numNodes - 1}.`
      );
      return;
    }

    if (this.initialNode === this.destinationNode) {
      alert('Source and destination nodes should be different.');
      return;
    }

    this.graph = Array.from({ length: this.numNodes }, () =>
      Array(this.numNodes).fill(0)
    );
    const edgesToRemove = new Set(['3-5', '3-1', '3-0', '0-4', '0-2', '4-1']);

    if (this.isDirected) {
      this.generateDirectedGraph(edgesToRemove);
    } else {
      this.generateUndirectedGraph(edgesToRemove);
    }
    this.ensurePathExists();
    this.runDijkstraAlgorithm();
  }

  // ======= THis function is used to generate the undirected graph =======
  generateUndirectedGraph(edgesToRemove: Set<string>): void {
    for (let i = 0; i < this.numNodes; i++) {
      for (let j = i + 1; j < this.numNodes; j++) {
        if (edgesToRemove.has(`${i}-${j}`) || edgesToRemove.has(`${j}-${i}`)) {
          this.graph[i][j] = 0;
          this.graph[j][i] = 0;
        } else {
          const weight = Math.floor(Math.random() * 10) + 1;
          this.graph[i][j] = weight;
          this.graph[j][i] = weight;
        }
      }
    }

    // For larger graphs, to reduce the connectivity to make it more readable and clear the paths
    if (this.numNodes >= 7) {
      for (let i = 0; i < this.numNodes; i++) {
        const neighbors = this.graph[i]
          .map((w, idx) => (w > 0 ? idx : -1))
          .filter((idx) => idx !== -1);
        while (neighbors.length > 3) {
          const removeIdx = Math.floor(Math.random() * neighbors.length);
          const removedNode = neighbors.splice(removeIdx, 1)[0];
          this.graph[i][removedNode] = 0;
          this.graph[removedNode][i] = 0;
        }
      }
    }
  }

  // ======= This function is used to generate the directed graph =======
  generateDirectedGraph(edgesToRemove: Set<string>): void {
    for (let i = 0; i < this.numNodes; i++) {
      for (let j = 0; j < this.numNodes; j++) {
        this.graph[i][j] = 0;
      }
    }
    const createdConnections = new Set<string>();

    for (let i = 0; i < this.numNodes; i++) {
      for (let j = 0; j < this.numNodes; j++) {
        if (i !== j) {
          if (edgesToRemove.has(`${i}-${j}`)) {
            continue;
          }

          if (createdConnections.has(`${j}-${i}`)) {
            continue;
          }

          if (Math.random() < 0.6) {
            const weight = Math.floor(Math.random() * 10) + 1;
            this.graph[i][j] = weight;
            createdConnections.add(`${i}-${j}`);
          }
        }
      }
    }
    if (this.numNodes >= 7) {
      for (let i = 0; i < this.numNodes; i++) {
        const outgoingEdges = this.graph[i]
          .map((w, idx) => (w > 0 ? idx : -1))
          .filter((idx) => idx !== -1);

        while (outgoingEdges.length > 3) {
          const removeIdx = Math.floor(Math.random() * outgoingEdges.length);
          const removedNode = outgoingEdges.splice(removeIdx, 1)[0];
          this.graph[i][removedNode] = 0;
        }
      }
    }
  }

  // ======= This function is used to Run BFS to check if destination is reachable from source
  ensurePathExists(): void {
    const visited = new Set<number>();
    const queue: number[] = [this.initialNode];
    visited.add(this.initialNode);

    let pathExists = false;

    while (queue.length > 0) {
      const node = queue.shift()!;

      if (node === this.destinationNode) {
        pathExists = true;
        break;
      }

      for (let neighbor = 0; neighbor < this.numNodes; neighbor++) {
        if (this.graph[node][neighbor] > 0 && !visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
    if (!pathExists) {
      if (Math.random() > 0.5) {
        const weight = Math.floor(Math.random() * 10) + 1;
        this.graph[this.initialNode][this.destinationNode] = weight;
      } else {
        let intermediate = Math.floor(Math.random() * this.numNodes);
        while (
          intermediate === this.initialNode ||
          intermediate === this.destinationNode
        ) {
          intermediate = Math.floor(Math.random() * this.numNodes);
        }

        const weight1 = Math.floor(Math.random() * 10) + 1;
        const weight2 = Math.floor(Math.random() * 10) + 1;

        this.graph[this.initialNode][intermediate] = weight1;
        this.graph[intermediate][this.destinationNode] = weight2;
      }
    }
  }

  // fromhere started traversing the nodes and after that on user commands it reset the nodes
  runDijkstraAlgorithm(): void {
    const dist = Array(this.numNodes).fill(Infinity);
    const visited = new Set<number>();
    const previous: number[] = Array(this.numNodes).fill(-1);
    this.steps = [];
    this.nodesVisited = [];
    dist[this.initialNode] = 0;
    this.steps.push({
      node: this.initialNode,
      explanation: `Starting at node ${this.initialNode} with distance 0.`,
    });
    this.nodesVisited.push(this.initialNode);
    const queue: number[] = [];
    for (let i = 0; i < this.numNodes; i++) {
      queue.push(i);
    }
    let destinationReached = false;
    while (queue.length > 0 && !destinationReached) {
      let minIdx = 0;
      for (let i = 1; i < queue.length; i++) {
        if (dist[queue[i]] < dist[queue[minIdx]]) {
          minIdx = i;
        }
      }
      const u = queue.splice(minIdx, 1)[0];
      if (dist[u] === Infinity) {
        continue;
      }
      if (u === this.destinationNode) {
        destinationReached = true;
        this.nodesVisited.push(u);
        this.steps.push({
          node: u,
          explanation: `Reached destination node ${u} with distance ${
            dist[u]
          }. Nodes traversed: ${this.nodesVisited.join(' → ')}`,
        });
        break;
      }

      visited.add(u);
      if (u !== this.initialNode) {
        this.nodesVisited.push(u);
      }
      this.steps.push({
        node: u,
        explanation: `Visited node ${u} with distance ${
          dist[u]
        }. Nodes traversed so far: ${this.nodesVisited.join(' → ')}`,
      });
      for (let v = 0; v < this.numNodes; v++) {
        if (this.graph[u][v] > 0 && !visited.has(v)) {
          const newDist = dist[u] + this.graph[u][v];
          if (newDist < dist[v]) {
            dist[v] = newDist;
            previous[v] = u;
            this.steps.push({
              node: v,
              explanation: `Updated distance to node ${v} via node ${u}: new distance = ${newDist}.`,
            });
          }
        }
      }
    }

    // ==== this command used to creat the shortest path
    this.buildPath(previous);
    this.resetAlgorithm();
    if (this.path.length > 1) {
      const distance = dist[this.destinationNode];
      const pathStr = this.path.join(' → ');
      this.pathDescription = `Shortest path from node ${this.initialNode} to node ${this.destinationNode}: ${pathStr}`;
      this.explanation = `${this.pathDescription} with total distance: ${distance}.`;
    } else {
      this.pathDescription = `No path found from node ${this.initialNode} to node ${this.destinationNode}.`;
      this.explanation = this.pathDescription;
    }
  }

  buildPath(previous: number[]): void {
    this.path = [];
    let current = this.destinationNode;
    if (previous[current] !== -1 || current === this.initialNode) {
      while (current !== -1) {
        this.path.unshift(current);
        current = previous[current];
      }
    }
  }
  resetAlgorithm(): void {
    this.currentStep = 0;
    this.selectedNode = null;
    this.isPlaying = false;
  }
  playAlgorithm(): void {
    if (this.currentStep < this.steps.length) {
      const currentStepData = this.steps[this.currentStep];
      this.selectedNode = currentStepData.node;
      this.explanation = currentStepData.explanation;
      this.currentStep++;
      if (this.currentStep === this.steps.length) {
        setTimeout(() => {
          this.explanation = this.pathDescription;
          this.selectedNode = null;
        }, 1000);
      }
    } else {
      this.resetAlgorithm();
    }
  }
  handlePlayPause(): void {
    this.isPlaying = !this.isPlaying;
    if (this.isPlaying) {
      this.autoPlay();
    }
  }
  autoPlay(): void {
    if (this.isPlaying && this.currentStep < this.steps.length) {
      setTimeout(() => {
        this.playAlgorithm();
        this.autoPlay();
      }, 1000);
    } else if (this.isPlaying) {
      this.isPlaying = false;
      this.explanation = this.pathDescription;
      this.selectedNode = null;
    }
  }
  toggleGraphType(): void {
    this.isDirected = !this.isDirected;
    this.generateGraph();
  }

  goBack(): void {
    window.history.back();
  }
}
