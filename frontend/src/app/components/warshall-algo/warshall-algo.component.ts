import {
  Component,
  OnInit,
  ViewChild,
  ElementRef,
  AfterViewInit,
  ViewEncapsulation,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NavbarComponent } from '../navbar/navbar.component';

interface Node {
  label: string;
  x: number;
  y: number;
}

interface Step {
  i: number;
  j: number;
  k: number;
  dist: number[][];
  improved: boolean;
}

@Component({
  selector: 'app-warshall-algo',
  templateUrl: './warshall-algo.component.html',
  styleUrls: ['./warshall-algo.component.css'],
  standalone: true,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, NavbarComponent],
})
export class WarshallAlgoComponent implements OnInit, AfterViewInit {
  @ViewChild('originalCanvas')
  originalCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('pathCanvas') pathCanvasRef!: ElementRef<HTMLCanvasElement>;
  numberOfNodes: number = 5;
  isDirected: boolean = true;
  nodes: Node[] = [];
  graph: number[][] = [];
  steps: Step[] = [];
  currentStep: number = 0;
  isAnimating: boolean = false;
  animationSpeed: number = 500;
  animationInterval: any;
  Number = Number;
  constructor() {}
  ngOnInit(): void {
    this.generateGraph();
  }

  ngAfterViewInit(): void {
    this.initializeCanvasSize();
    this.drawGraph();
    window.addEventListener('resize', () => {
      this.initializeCanvasSize();
      this.drawGraph();
    });
  }

  // This methodd is used to initialize the canvas size based on the parent element's size ==
  initializeCanvasSize(): void {
    const originalCanvas = this.originalCanvasRef.nativeElement;
    const pathCanvas = this.pathCanvasRef.nativeElement;

    const container = originalCanvas.parentElement;
    if (container) {
      const width = container.clientWidth;
      const height = container.clientHeight;

      originalCanvas.width = width;
      originalCanvas.height = height;
      pathCanvas.width = width;
      pathCanvas.height = height;
    }

    this.calculateNodePositions();
  }

  // === This methos is used to calculate the positions of the nodes in the graph==
  calculateNodePositions(): void {
    const radius = 150;
    const centerX = this.originalCanvasRef.nativeElement.width / 2;
    const centerY = this.originalCanvasRef.nativeElement.height / 2;

    this.nodes = [];
    for (let i = 0; i < this.numberOfNodes; i++) {
      const angle = (i * 2 * Math.PI) / this.numberOfNodes;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      this.nodes.push({
        label: String.fromCharCode(65 + i),
        x,
        y,
      });
    }
  }

  // === This method is used to generate the graph with random weights and connections ===
  generateGraph(): void {
    this.calculateNodePositions();
    this.graph = Array(this.numberOfNodes)
      .fill(0)
      .map(() => Array(this.numberOfNodes).fill(Number.POSITIVE_INFINITY));

    for (let i = 0; i < this.numberOfNodes; i++) {
      this.graph[i][i] = 0;
      for (let j = 0; j < this.numberOfNodes; j++) {
        if (i !== j) {
          if (Math.random() < 0.4) {
            const weight = Math.floor(Math.random() * 9) + 1;
            this.graph[i][j] = weight;
            if (!this.isDirected) {
              this.graph[j][i] = weight;
            }
          }
        }
      }
    }
    this.resetAlgorithm();
    this.drawGraph();
  }

  // === This method is used to draw the graph on the canvas ===
  drawGraph(): void {
    if (!this.originalCanvasRef || !this.pathCanvasRef) return;
    const originalCtx = this.originalCanvasRef.nativeElement.getContext('2d');
    const pathCtx = this.pathCanvasRef.nativeElement.getContext('2d');
    if (!originalCtx || !pathCtx) return;
    originalCtx.clearRect(
      0,
      0,
      this.originalCanvasRef.nativeElement.width,
      this.originalCanvasRef.nativeElement.height
    );
    pathCtx.clearRect(
      0,
      0,
      this.pathCanvasRef.nativeElement.width,
      this.pathCanvasRef.nativeElement.height
    );

    this.nodes.forEach((node) => {
      [originalCtx, pathCtx].forEach((ctx) => {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 20, 0, 2 * Math.PI);
        ctx.fillStyle = '#4682B4';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = 'white';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.font = '16px Arial';
        ctx.fillText(node.label, node.x, node.y);
      });
    });

    // === Draw edges on the original canvas ===
    for (let i = 0; i < this.numberOfNodes; i++) {
      for (let j = 0; j < this.numberOfNodes; j++) {
        if (i !== j && this.graph[i][j] !== Number.POSITIVE_INFINITY) {
          const startNode = this.nodes[i];
          const endNode = this.nodes[j];
          this.drawEdge(
            originalCtx,
            startNode,
            endNode,
            this.graph[i][j],
            this.isDirected
          );
        }
      }
    }
  }

  // === This method is used to draw the edges between the nodes ====
  drawEdge(
    ctx: CanvasRenderingContext2D,
    from: Node,
    to: Node,
    weight: number,
    directed: boolean
  ): void {
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    const startRadius = 20;
    const startX = from.x + (dx * startRadius) / distance;
    const startY = from.y + (dy * startRadius) / distance;
    const endRadius = 20;
    const endX = to.x - (dx * endRadius) / distance;
    const endY = to.y - (dy * endRadius) / distance;
    ctx.beginPath();
    ctx.moveTo(startX, startY);
    ctx.lineTo(endX, endY);
    ctx.strokeStyle = '#555';
    ctx.lineWidth = 2;
    ctx.stroke();

    if (directed) {
      const headLen = 10;
      const angle = Math.atan2(dy, dx);
      ctx.beginPath();
      ctx.moveTo(endX, endY);
      ctx.lineTo(
        endX - headLen * Math.cos(angle - Math.PI / 6),
        endY - headLen * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        endX - headLen * Math.cos(angle + Math.PI / 6),
        endY - headLen * Math.sin(angle + Math.PI / 6)
      );
      ctx.closePath();
      ctx.fillStyle = '#555';
      ctx.fill();
    }

    // ===== Draw weight label above the edge
    const labelX = (startX + endX) / 2;
    const labelY = (startY + endY) / 2;
    const offset = 15;
    const angle = Math.atan2(dy, dx);
    const offsetX = -offset * Math.sin(angle);
    const offsetY = offset * Math.cos(angle);
    ctx.fillStyle = '#333';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = '12px Arial';
    ctx.fillText(weight.toString(), labelX + offsetX, labelY + offsetY);
  }

  // === This method is used to run the floyd-warshall algorithm ===
  floydWarshall(): void {
    const n = this.numberOfNodes;
    const dist: number[][] = [];
    for (let i = 0; i < n; i++) {
      dist[i] = [...this.graph[i]];
    }
    this.steps = [
      {
        i: -1,
        j: -1,
        k: -1,
        dist: JSON.parse(JSON.stringify(dist)),
        improved: false,
      },
    ];

    // === Floyd-Warshall algorithmslogic for traversing the nodes
    for (let k = 0; k < n; k++) {
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
          const throughK = dist[i][k] + dist[k][j];
          const improved =
            dist[i][k] !== Number.POSITIVE_INFINITY &&
            dist[k][j] !== Number.POSITIVE_INFINITY &&
            throughK < dist[i][j];

          if (improved) {
            dist[i][j] = throughK;
          }
          this.steps.push({
            i,
            j,
            k,
            dist: JSON.parse(JSON.stringify(dist)),
            improved,
          });
        }
      }
    }
    this.currentStep = 0;
  }

  resetAlgorithm(): void {
    this.stopAnimation();
    this.currentStep = 0;
    this.steps = [];
    this.floydWarshall();
    this.drawGraph();
  }

  startAnimation(): void {
    if (this.isAnimating || this.steps.length === 0) return;
    this.isAnimating = true;
    this.animationInterval = setInterval(() => {
      this.nextStep();
      if (this.currentStep >= this.steps.length - 1) {
        this.stopAnimation();
      }
    }, this.animationSpeed);
  }

  stopAnimation(): void {
    if (this.animationInterval) {
      clearInterval(this.animationInterval);
    }
    this.isAnimating = false;
  }

  nextStep(): void {
    if (this.currentStep < this.steps.length - 1) {
      this.currentStep++;
      this.updatePathCanvas();
    }
  }

  prevStep(): void {
    if (this.currentStep > 0) {
      this.currentStep--;
      this.updatePathCanvas();
    }
  }

  updatePathCanvas(): void {
    if (!this.pathCanvasRef) return;

    const pathCtx = this.pathCanvasRef.nativeElement.getContext('2d');
    if (!pathCtx) return;
    pathCtx.clearRect(
      0,
      0,
      this.pathCanvasRef.nativeElement.width,
      this.pathCanvasRef.nativeElement.height
    );
    this.nodes.forEach((node) => {
      pathCtx.beginPath();
      pathCtx.arc(node.x, node.y, 20, 0, 2 * Math.PI);
      pathCtx.fillStyle = '#4682B4';
      pathCtx.fill();
      pathCtx.stroke();
      pathCtx.fillStyle = 'white';
      pathCtx.textAlign = 'center';
      pathCtx.textBaseline = 'middle';
      pathCtx.font = '16px Arial';
      pathCtx.fillText(node.label, node.x, node.y);
    });

    // If we have steps, draw current paths
    if (this.currentStep > 0) {
      const step = this.steps[this.currentStep];

      // for highlighting the active nodes in the current step
      if (step.i >= 0 && step.j >= 0 && step.k >= 0) {
        const nodeI = this.nodes[step.i];
        const nodeJ = this.nodes[step.j];
        const nodeK = this.nodes[step.k];

        // for highlighting the source nodes
        pathCtx.beginPath();
        pathCtx.arc(nodeI.x, nodeI.y, 22, 0, 2 * Math.PI);
        pathCtx.strokeStyle = '#FF5733';
        pathCtx.lineWidth = 3;
        pathCtx.stroke();

        // for highlighting the destination nodes
        pathCtx.beginPath();
        pathCtx.arc(nodeJ.x, nodeJ.y, 22, 0, 2 * Math.PI);
        pathCtx.strokeStyle = '#33FF57';
        pathCtx.lineWidth = 3;
        pathCtx.stroke();

        // for highlighting the intermediate nodes
        pathCtx.beginPath();
        pathCtx.arc(nodeK.x, nodeK.y, 22, 0, 2 * Math.PI);
        pathCtx.strokeStyle = '#3357FF';
        pathCtx.lineWidth = 3;
        pathCtx.stroke();

        // the after findingthe nodes, draw the paths
        if (step.dist[step.i][step.k] !== Number.POSITIVE_INFINITY) {
          this.drawPath(pathCtx, nodeI, nodeK, '#FF8C33');
        }
        if (step.dist[step.k][step.j] !== Number.POSITIVE_INFINITY) {
          this.drawPath(pathCtx, nodeK, nodeJ, '#33FF8C');
        }
        if (step.dist[step.i][step.j] !== Number.POSITIVE_INFINITY) {
          this.drawPath(
            pathCtx,
            nodeI,
            nodeJ,
            step.improved ? '#FF33FF' : '#777777'
          );
        }
      }
    }
  }

  drawPath(
    ctx: CanvasRenderingContext2D,
    from: Node,
    to: Node,
    color: string
  ): void {
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    const startRadius = 20;
    const startX = from.x + (dx * startRadius) / distance;
    const startY = from.y + (dy * startRadius) / distance;
    const endRadius = 20;
    const endX = to.x - (dx * endRadius) / distance;
    const endY = to.y - (dy * endRadius) / distance;

    // Draw the line like a path
    ctx.beginPath();
    ctx.moveTo(startX, startY);
    ctx.lineTo(endX, endY);
    ctx.strokeStyle = color;
    ctx.lineWidth = 3;
    ctx.stroke();
    const headLen = 10;
    const angle = Math.atan2(dy, dx);
    ctx.beginPath();
    ctx.moveTo(endX, endY);
    ctx.lineTo(
      endX - headLen * Math.cos(angle - Math.PI / 6),
      endY - headLen * Math.sin(angle - Math.PI / 6)
    );
    ctx.lineTo(
      endX - headLen * Math.cos(angle + Math.PI / 6),
      endY - headLen * Math.sin(angle + Math.PI / 6)
    );
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();

    // for drawing weight labels above the edges
    const labelX = (startX + endX) / 2;
    const labelY = (startY + endY) / 2;

    const offset = 15;
    const offsetX = -offset * Math.sin(angle);
    const offsetY = offset * Math.cos(angle);
    ctx.fillStyle = '#333';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = '12px Arial';
    ctx.fillText(
      this.graph[this.nodes.indexOf(from)][this.nodes.indexOf(to)].toString(),
      labelX + offsetX,
      labelY + offsetY
    );
  }

  // === This method is used to check if the edge between two nodes is un the shortest path ornot ===
  isInShortestPath(i: number, j: number): boolean {
    if (this.currentStep <= 0 || i === j) return false;
    const step = this.steps[this.currentStep];
    return (
      i === step.i &&
      j === step.j &&
      step.dist[i][j] !== Number.POSITIVE_INFINITY
    );
  }

  goBack(): void {
    window.history.back();
  }
}
