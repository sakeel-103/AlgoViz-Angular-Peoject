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
  styleUrls: ['./prims-algo.component.css'],
})
export class GraphCanvasWrapperComponent implements OnChanges {
  @Input() graph: number[][] = [];
  @Input() mstEdges: { u: number; v: number; weight: number }[] = [];
  @Input() showWeights: boolean = true;
  @Input() selectedNode: number | null = null;
  @Input() selectedEdge: { u: number; v: number; weight: number } | null = null;
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

  //  ==== this function draws the graph on the canvas using the provided graphs ===
  drawGraph(): void {
    if (!this.ctx) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, 500, 400);
    const radius = 20;
    const centerX = 250;
    const centerY = 200;
    const angleStep = (2 * Math.PI) / this.graph.length;
    const positions: { x: number; y: number }[] = [];

    for (let i = 0; i < this.graph.length; i++) {
      const x = centerX + 150 * Math.cos(i * angleStep);
      const y = centerY + 150 * Math.sin(i * angleStep);
      positions.push({ x, y });
    }

    for (let u = 0; u < this.graph.length; u++) {
      for (let v = u + 1; v < this.graph.length; v++) {
        if (this.graph[u][v] > 0) {
          ctx.beginPath();
          ctx.moveTo(positions[u].x, positions[u].y);
          ctx.lineTo(positions[v].x, positions[v].y);
          const isTraversed = this.mstEdges.some(
            (edge) =>
              (edge.u === u && edge.v === v) || (edge.u === v && edge.v === u)
          );
          ctx.strokeStyle = isTraversed
            ? 'green'
            : this.selectedEdge &&
              this.selectedEdge.u === u &&
              this.selectedEdge.v === v
            ? 'red'
            : 'black';
          ctx.lineWidth =
            this.selectedEdge &&
            this.selectedEdge.u === u &&
            this.selectedEdge.v === v
              ? 3
              : 1;
          ctx.stroke();

          if (this.showWeights) {
            const midX = (positions[u].x + positions[v].x) / 2;
            const midY = (positions[u].y + positions[v].y) / 2;
            ctx.fillStyle = 'black';
            ctx.font = '20px Arial';
            ctx.fillText(this.graph[u][v].toString(), midX, midY);
          }
        }
      }
    }

    for (let i = 0; i < this.graph.length; i++) {
      ctx.beginPath();
      ctx.arc(positions[i].x, positions[i].y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = this.selectedNode === i ? 'green' : 'white';
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = 'black';
      ctx.fillText(i.toString(), positions[i].x - 5, positions[i].y + 5);
    }
  }
}

@Component({
  selector: 'app-prims-algo',
  standalone: true,
  templateUrl: './prims-algo.component.html',
  styleUrls: ['./prims-algo.component.css'],
  imports: [
    FormsModule,
    CommonModule,
    NavbarComponent,
    GraphCanvasWrapperComponent,
  ],
  encapsulation: ViewEncapsulation.None,
})
export class PrimsAlgoComponent {
  numNodes: number = 5;
  initialNode: number = 0;
  graph: number[][] = [];
  mstEdges: { u: number; v: number; weight: number }[] = [];
  steps: {
    edge: { u: number; v: number; weight: number };
    explanation: string;
  }[] = [];
  currentStep: number = 0;
  isPlaying: boolean = false;
  selectedNode: number | null = null;
  selectedEdge: { u: number; v: number; weight: number } | null = null;
  explanation: string = '';
  showWeights: boolean = true;

  // ==== this function generates a random graph with specified number of nodes ===

  generateGraph(): void {
    if (this.numNodes < 5 || this.numNodes > 15) {
      alert('Please enter a number of nodes between 5 and 15.');
      return;
    }

    if (this.initialNode < 0 || this.initialNode >= this.numNodes) {
      alert(
        `Please select an initial node between 0 and ${this.numNodes - 1}.`
      );
      return;
    }

    this.graph = Array.from({ length: this.numNodes }, () =>
      Array(this.numNodes).fill(0)
    );

    for (let i = 0; i < this.numNodes; i++) {
      for (let j = i + 1; j < this.numNodes; j++) {
        const weight = Math.floor(Math.random() * 10) + 1;
        this.graph[i][j] = weight;
        this.graph[j][i] = weight;
      }
    }
    this.runPrimsAlgorithm();
  }

  // =========== This function runs Prim's algorithm to find the MST of the graph ======
  runPrimsAlgorithm(): void {
    this.mstEdges = [];
    const visited = new Set<number>([this.initialNode]);
    this.steps = [];

    while (visited.size < this.numNodes) {
      let minWeight = Infinity;
      let minEdge: { u: number; v: number; weight: number } | null = null;

      for (let u of visited) {
        for (let v = 0; v < this.numNodes; v++) {
          if (
            !visited.has(v) &&
            this.graph[u][v] > 0 &&
            this.graph[u][v] < minWeight
          ) {
            minWeight = this.graph[u][v];
            minEdge = { u, v, weight: this.graph[u][v] };
          }
        }
      }

      if (!minEdge) break;

      this.mstEdges.push(minEdge);
      this.steps.push({
        edge: minEdge,
        explanation: `Selected edge (${minEdge.u}, ${minEdge.v}) with weight ${minEdge.weight}.`,
      });
      visited.add(minEdge.v);
    }
    this.resetAlgorithm();
  }

  resetAlgorithm(): void {
    this.currentStep = 0;
    this.selectedNode = null;
    this.selectedEdge = null;
    this.explanation = '';
    this.isPlaying = false;
  }
  playAlgorithm(): void {
    if (this.currentStep < this.steps.length) {
      const currentStepData = this.steps[this.currentStep];
      this.selectedNode = currentStepData.edge.v;
      this.selectedEdge = currentStepData.edge;
      this.explanation = currentStepData.explanation;
      this.currentStep++;
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
    }
  }

  goBack(): void {
    window.history.back();
  }
}
