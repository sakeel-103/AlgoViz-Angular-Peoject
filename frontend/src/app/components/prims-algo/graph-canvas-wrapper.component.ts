// import {
//   Component,
//   ElementRef,
//   Input,
//   ViewChild,
//   AfterViewInit,
//   OnChanges,
//   SimpleChanges,
// } from '@angular/core';

// @Component({
//   selector: 'app-graph-canvas-wrapper',
//   template: `
//     <div class="canvas-container">
//       <canvas #graphCanvas width="500" height="400"></canvas>
//     </div>
//   `,
//   styleUrls: ['./prims-algo.component.css'],
// })
// export class GraphCanvasWrapperComponent implements AfterViewInit, OnChanges {
//   @Input() graph: number[][] = [];
//   @Input() mstEdges: { u: number; v: number; weight: number }[] = [];
//   @Input() selectedEdge: { u: number; v: number; weight: number } | null = null;
//   @Input() selectedNode: number | null = null;

//   @ViewChild('graphCanvas', { static: false })
//   canvas!: ElementRef<HTMLCanvasElement>;
//   private ctx!: CanvasRenderingContext2D;

//   ngAfterViewInit(): void {
//     this.ctx = this.canvas.nativeElement.getContext('2d')!;
//     this.drawGraph();
//   }

//   ngOnChanges(changes: SimpleChanges): void {
//     if (this.ctx) {
//       this.drawGraph();
//     }
//   }

//   drawGraph(): void {
//     const nodeRadius = 30;
//     const nodePositions = this.getNodePositions(this.graph.length);

//     this.ctx.clearRect(0, 0, 500, 400);

//     // Draw MST Edges with Animation in Order
//     this.mstEdges.forEach(({ u, v, weight }, index) => {
//       setTimeout(() => {
//         this.ctx.beginPath();
//         this.ctx.moveTo(nodePositions[u].x, nodePositions[u].y);
//         this.ctx.lineTo(nodePositions[v].x, nodePositions[v].y);
//         this.ctx.strokeStyle =
//           this.selectedEdge?.u === u && this.selectedEdge?.v === v
//             ? 'red'
//             : 'green';
//         this.ctx.lineWidth = 3;
//         this.ctx.stroke();

//         const midX = (nodePositions[u].x + nodePositions[v].x) / 2;
//         const midY = (nodePositions[u].y + nodePositions[v].y) / 2;
//         this.ctx.fillStyle = 'blue';
//         this.ctx.fillText(weight.toString(), midX, midY);
//       }, index * 1000);
//     });

//     // Draw Nodes
//     nodePositions.forEach(({ x, y }, i) => {
//       this.ctx.beginPath();
//       this.ctx.arc(x, y, nodeRadius, 0, 2 * Math.PI);
//       this.ctx.fillStyle = this.selectedNode === i ? 'green' : 'yellow';
//       this.ctx.fill();
//       this.ctx.stroke();
//       this.ctx.fillStyle = 'black';
//       this.ctx.fillText(i.toString(), x - 5, y + 5);
//     });
//   }

//   getNodePositions(n: number): { x: number; y: number }[] {
//     const positions: { x: number; y: number }[] = [];
//     const radius = 150;
//     const centerX = 250;
//     const centerY = 200;

//     for (let i = 0; i < n; i++) {
//       const angle = (2 * Math.PI * i) / n;
//       const x = centerX + radius * Math.cos(angle);
//       const y = centerY + radius * Math.sin(angle);
//       positions.push({ x, y });
//     }

//     return positions;
//   }
// }
